/*
 *      Copyright (C) 2005-2013 Team XBMC
 *      http://xbmc.org
 *
 *  This Program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This Program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with XBMC; see the file COPYING.  If not, see
 *  <http://www.gnu.org/licenses/>.
 *
 */

#include "threads/SystemClock.h"
#include "utils/AutoPtrHandle.h"
#include "FileCache.h"
#include "threads/Thread.h"
#include "File.h"
#include "URL.h"

#include "CircularCache.h"
#include "threads/SingleLock.h"
#include "utils/log.h"
#include "utils/TimeUtils.h"
#include "settings/AdvancedSettings.h"

using namespace AUTOPTR;
using namespace XFILE;

#define READ_CACHE_CHUNK_SIZE (64*1024)
#define ASYNC_READ_AGAIN -2

class CWriteRate
{
public:
  CWriteRate()
  {
    m_stamp = XbmcThreads::SystemClockMillis();
    m_pos   = 0;
    m_pause = 0;
  }

  void Reset(int64_t pos)
  {
    m_stamp = XbmcThreads::SystemClockMillis();
    m_pos   = pos;
  }

  unsigned Rate(int64_t pos, unsigned int time_bias = 0)
  {
    const unsigned ts = XbmcThreads::SystemClockMillis() + time_bias;
    if (ts == m_stamp)
      return 0;
    return (unsigned)(1000 * (pos - m_pos) / (ts - m_stamp));
  }

  void Pause()
  {
    m_pause = XbmcThreads::SystemClockMillis();
  }

  void Resume()
  {
    m_stamp += XbmcThreads::SystemClockMillis() - m_pause;
    m_pause  = 0;
  }

private:
  unsigned m_stamp;
  int64_t  m_pos;
  unsigned m_pause;
};


CFileCache::CFileCache(bool useDoubleCache) : CThread("FileCache")
{
   m_bDeleteCache = true;
   m_nSeekResult = 0;
   m_seekPos = 0;
   m_readPos = 0;
   m_writePos = 0;
   if (g_advancedSettings.m_cacheMemBufferSize == 0)
     m_pCache = new CSimpleFileCache();
   else
   {
     size_t front = g_advancedSettings.m_cacheMemBufferSize;
     size_t back = std::max<size_t>( g_advancedSettings.m_cacheMemBufferSize / 4, 1024 * 1024);
     if (useDoubleCache)
     {
       front = front / 2;
       back = back / 2;
     }
     m_pCache = new CCircularCache(front, back);
   }
   if (useDoubleCache)
   {
     m_pCache = new CSimpleDoubleCache(m_pCache);
   }
   m_seekPossible = 0;
   m_cacheFull = false;
}

CFileCache::CFileCache(CCacheStrategy *pCache, bool bDeleteCache) : CThread("FileCacheStrategy")
{
  m_pCache = pCache;
  m_bDeleteCache = bDeleteCache;
  m_seekPos = 0;
  m_readPos = 0;
  m_writePos = 0;
  m_nSeekResult = 0;
  m_chunkSize = 0;
}

CFileCache::~CFileCache()
{
  Close();

  if (m_bDeleteCache && m_pCache)
    delete m_pCache;

  m_pCache = NULL;
}

void CFileCache::SetCacheStrategy(CCacheStrategy *pCache, bool bDeleteCache)
{
  if (m_bDeleteCache && m_pCache)
    delete m_pCache;

  m_pCache = pCache;
  m_bDeleteCache = bDeleteCache;
}

IFile *CFileCache::GetFileImp()
{
  return m_source.GetImplemenation();
}

bool CFileCache::Open(const CURL& url)
{
  Close();

  CSingleLock lock(m_sync);

  CLog::Log(LOGDEBUG,"CFileCache::Open - opening <%s> using cache", url.GetFileName().c_str());

  if (!m_pCache)
  {
    CLog::Log(LOGERROR,"CFileCache::Open - no cache strategy defined");
    return false;
  }

  m_sourcePath = url.Get();

  // open cache strategy
  if (m_pCache->Open() != CACHE_RC_OK)
  {
    CLog::Log(LOGERROR,"CFileCache::Open - failed to open cache");
    Close();
    return false;
  }

  // opening the source file.
  if (!m_source.Open(m_sourcePath, READ_NO_CACHE | READ_TRUNCATED | READ_CHUNKED))
  {
    CLog::Log(LOGERROR,"%s - failed to open source <%s>", __FUNCTION__, url.GetRedacted().c_str());
    Close();
    return false;
  }

  m_source.IoControl(IOCTRL_SET_CACHE,this);

  // check if source can seek
  m_seekPossible = m_source.IoControl(IOCTRL_SEEK_POSSIBLE, NULL);
  m_chunkSize = CFile::GetChunkSize(m_source.GetChunkSize(), READ_CACHE_CHUNK_SIZE);

  m_readPos = 0;
  m_writePos = 0;
  m_writeRate = 1024 * 1024;
  m_writeRateActual = 0;
  m_cacheFull = false;
  m_seekEvent.Reset();
  m_seekEnded.Reset();

  CThread::Create(false);

  return true;
}

/**
 * Fills the buffer of this cached file
 *
 * This method will read a chunk of data from the source file
 * and write it to the buffer according to the cache strategy.
 * It keeps doing this unless read or write errors were found.
 */
void CFileCache::Process()
{
  CLog::Log(LOGDEBUG, "***** Starting Process() *****");
  CLog::Log(LOGERROR, "***** Deque size at start of Process() is %ld *****", m_readBufferArray.size());
  if (!m_pCache)
  {
    CLog::Log(LOGERROR,"CFileCache::Process - sanity failed. no cache strategy");
    return;
  }
  // TODO put a limit on the amount of outstanding read requests you can have

  CWriteRate limiter;
  CWriteRate average;
  bool cacheReachEOF = false;

  CLog::Log(LOGDEBUG, "***** Starting while loop *****");
  
  while (!m_bStop)
  {
	CLog::Log(LOGERROR, "***** Starting Process() loop iteration *****");
    // check for seek events
    if (m_seekEvent.WaitMSec(0))
    {
	  CLog::Log(LOGERROR, "***** Starting Seek Event section *****");
      m_seekEvent.Reset();
      int64_t cacheMaxPos = m_pCache->CachedDataEndPosIfSeekTo(m_seekPos);
      cacheReachEOF = cacheMaxPos == m_source.GetLength();
      bool sourceSeekFailed = false;
      if (!cacheReachEOF)
      {
        m_readBufferArray.clear();
        CLog::Log(LOGERROR, "***** Cleared read buffer due to seek event *****");
        m_nSeekResult = m_source.Seek(cacheMaxPos, SEEK_SET);
        if (m_nSeekResult != cacheMaxPos)
        {
          CLog::Log(LOGERROR,"CFileCache::Process - Error %d seeking. Seek returned %" PRId64, (int)GetLastError(), m_nSeekResult);
          m_seekPossible = m_source.IoControl(IOCTRL_SEEK_POSSIBLE, NULL);
          sourceSeekFailed = true;
        }
      }
      if (!sourceSeekFailed)
      {
        m_pCache->Reset(m_seekPos, false);
        m_readPos = m_seekPos;
        m_writePos = m_pCache->CachedDataEndPos();
        assert(m_writePos == cacheMaxPos);
        average.Reset(m_writePos);
        limiter.Reset(m_writePos);
        m_cacheFull = false;
        m_nSeekResult = m_seekPos;
      }

      m_seekEnded.Set();
	  CLog::Log(LOGERROR, "***** Ending Seek Event section *****");
    }

    while (m_writeRate)
    {
	  CLog::Log(LOGERROR, "***** Starting writeRate checking *****");
      if (m_writePos - m_readPos < m_writeRate)
      {
        limiter.Reset(m_writePos);
        break;
      }

      if (limiter.Rate(m_writePos) < m_writeRate)
        break;

      if (m_seekEvent.WaitMSec(100))
      {
        m_seekEvent.Set();
        break;
      }
      CLog::Log(LOGERROR, "***** Done with writeRate checking *****");
    }

    // Create a new buffer and add it to the deque
    auto_aptr<char> readBuf (new char[m_chunkSize]);
    if (readBuf.get() == NULL) {
      CLog::Log(LOGERROR, "%s - failed to allocate read buffer", __FUNCTION__);
      return;
    }
    CLog::Log(LOGERROR, "***** created read buffer: %p *****", readBuf.get());
    int iRead = 0;
    if (!cacheReachEOF){
      // Read a chunk from the source into the buffer
      iRead = m_source.Read(readBuf.get(), m_chunkSize);
      CLog::Log(LOGERROR, "***** Reading chunk returned: %d *****", iRead);
      /*
       * For async reads to work, the Read() call should return values as follows:
       * - number of bytes read:      when the read has been completed and all data read into the buffer
       * - 0:                         when the read has been completed and has reached EOF
       * - ASYNC_READ_AGAIN (-2):     when the read has not been completed yet
       * - any other negative number: when an error has occurred during reading
       * Note that this is compatible with synchronous reads, as long as it doesn't return -2 as an error code
       */

      // Add the current chunk's details to the deque
      FileCacheChunk_t currentChunk;
      currentChunk.readBuffer = readBuf;
      currentChunk.readResult = iRead;
      m_readBufferArray.push_back(currentChunk);
      readBuf.release();
    }
    if (iRead == 0)
    {
      CLog::Log(LOGINFO, "CFileCache::Process - Hit eof.");
      m_pCache->EndOfInput();

      // The thread event will now also cause the wait of an event to return a false.
      if (AbortableWait(m_seekEvent) == WAIT_SIGNALED)
      {
        m_pCache->ClearEndOfInput();
        m_seekEvent.Set(); // hack so that later we realize seek is needed
      }
      else
        break;
    }
    else if (iRead < 0){
      CLog::Log(LOGERROR, "***** Starting error check section *****");
      // Check if the read request was completed
      if (iRead != ASYNC_READ_AGAIN){
        CLog::Log(LOGERROR, "***** Error found during read request *****");
        // The read request was completed and returned an error, so we should stop processing
        m_bStop = true;
      }
      CLog::Log(LOGERROR, "***** Finished error check section *****");
    }
    CLog::Log(LOGERROR, "***** Starting buffer write section *****");
    CLog::Log(LOGERROR, "***** Deque size before loop is %ld *****", m_readBufferArray.size());
    // Write all available buffers to the cache
    while (!m_bStop && !m_readBufferArray.empty() && m_readBufferArray.front().readResult > 0) {
      CLog::Log(LOGERROR, "***** Started buffer write loop (checking each chunk on the deque) *****");
      int curChunkReadResult = m_readBufferArray.front().readResult;
      int iTotalWrite=0;
      while (!m_bStop && (iTotalWrite < curChunkReadResult)) {
        CLog::Log(LOGERROR, "***** Started buffer write loop (actually writing the chunk to the main cache) *****");
        int iWrite = 0;
        iWrite = m_pCache->WriteToCache(m_readBufferArray.front().readBuffer.get()+iTotalWrite, curChunkReadResult - iTotalWrite);

        // write should always work. all handling of buffering and errors should be
        // done inside the cache strategy. only if unrecoverable error happened, WriteToCache would return error and we break.
        if (iWrite < 0)
        {
          CLog::Log(LOGERROR,"CFileCache::Process - error writing to cache");
          m_bStop = true;
          break;
        }
        else if (iWrite == 0)
        {
          CLog::Log(LOGERROR, "***** Can't write any more of chunk to main cache, cache is full *****");
          /*
           * Cache is full so it can not be written to,
           * wait 5ms before trying again
           * (but don't count this time towards the average write rate)
           */
          m_cacheFull = true;
          average.Pause();
          m_pCache->m_space.WaitMSec(5);
          average.Resume();
          CLog::Log(LOGERROR, "***** configured for cache to free up space *****");
        }
        else{
          CLog::Log(LOGERROR, "***** Buffer successfully written to cache *****");
          // writing was successful, we can remove the chunk from the deque
          m_readBufferArray.pop_front();
          m_cacheFull = false;
          CLog::Log(LOGERROR, "***** Deque size is now %ld *****", m_readBufferArray.size());
        }

        iTotalWrite += iWrite;

        // check if seek was asked. otherwise if cache is full we'll freeze.
        if (m_seekEvent.WaitMSec(0))
        {
          m_seekEvent.Set(); // make sure we get the seek event later.
          break;
        }
      }
      m_writePos += iTotalWrite;

      // under estimate write rate by a second, to
      // avoid uncertainty at start of caching
      m_writeRateActual = average.Rate(m_writePos, 1000);
    }
  }
  CLog::Log(LOGERROR, "***** Deque size at end of Process() is %ld *****", m_readBufferArray.size());
}

void CFileCache::OnExit()
{
  m_bStop = true;

  // make sure cache is set to mark end of file (read may be waiting).
  if (m_pCache)
    m_pCache->EndOfInput();

  // just in case someone's waiting...
  m_seekEnded.Set();
}

bool CFileCache::Exists(const CURL& url)
{
  return CFile::Exists(url.Get());
}

int CFileCache::Stat(const CURL& url, struct __stat64* buffer)
{
  return CFile::Stat(url.Get(), buffer);
}

unsigned int CFileCache::Read(void* lpBuf, int64_t uiBufSize)
{
  CSingleLock lock(m_sync);
  if (!m_pCache)
  {
    CLog::Log(LOGERROR,"%s - sanity failed. no cache strategy!", __FUNCTION__);
    return 0;
  }
  int64_t iRc;

retry:
  // attempt to read
  iRc = m_pCache->ReadFromCache((char *)lpBuf, (size_t)uiBufSize);
  if (iRc > 0)
  {
    m_readPos += iRc;
    return (int)iRc;
  }

  if (iRc == CACHE_RC_WOULD_BLOCK)
  {
    // just wait for some data to show up
    iRc = m_pCache->WaitForData(1, 10000);
    if (iRc > 0)
      goto retry;
  }

  if (iRc == CACHE_RC_TIMEOUT)
  {
    CLog::Log(LOGWARNING, "%s - timeout waiting for data", __FUNCTION__);
    return 0;
  }

  if (iRc == 0)
    return 0;

  // unknown error code
  CLog::Log(LOGERROR, "%s - cache strategy returned unknown error code %d", __FUNCTION__, (int)iRc);
  return 0;
}

int64_t CFileCache::Seek(int64_t iFilePosition, int iWhence)
{
  CSingleLock lock(m_sync);

  if (!m_pCache)
  {
    CLog::Log(LOGERROR,"%s - sanity failed. no cache strategy!", __FUNCTION__);
    return -1;
  }

  int64_t iCurPos = m_readPos;
  int64_t iTarget = iFilePosition;
  if (iWhence == SEEK_END)
    iTarget = GetLength() + iTarget;
  else if (iWhence == SEEK_CUR)
    iTarget = iCurPos + iTarget;
  else if (iWhence != SEEK_SET)
    return -1;

  if (iTarget == m_readPos)
    return m_readPos;

  if ((m_nSeekResult = m_pCache->Seek(iTarget)) != iTarget)
  {
    if (m_seekPossible == 0)
      return m_nSeekResult;

    /* never request closer to end than 2k, speeds up tag reading */
    m_seekPos = std::min(iTarget, std::max((int64_t)0, m_source.GetLength() - m_chunkSize));

    m_seekEvent.Set();
    if (!m_seekEnded.Wait())
    {
      CLog::Log(LOGWARNING,"%s - seek to %" PRId64" failed.", __FUNCTION__, m_seekPos);
      return -1;
    }

    /* wait for any remainin data */
    if(m_seekPos < iTarget)
    {
      CLog::Log(LOGDEBUG,"%s - waiting for position %" PRId64".", __FUNCTION__, iTarget);
      if(m_pCache->WaitForData((unsigned)(iTarget - m_seekPos), 10000) < iTarget - m_seekPos)
      {
        CLog::Log(LOGWARNING,"%s - failed to get remaining data", __FUNCTION__);
        return -1;
      }
      m_pCache->Seek(iTarget);
    }
    m_readPos = iTarget;
    m_seekEvent.Reset();
  }
  else
    m_readPos = iTarget;

  return m_nSeekResult;
}

void CFileCache::Close()
{
  StopThread();

  CSingleLock lock(m_sync);
  if (m_pCache)
    m_pCache->Close();

  m_source.Close();
}

int64_t CFileCache::GetPosition()
{
  return m_readPos;
}

int64_t CFileCache::GetLength()
{
  return m_source.GetLength();
}

void CFileCache::StopThread(bool bWait /*= true*/)
{
  m_bStop = true;
  //Process could be waiting for seekEvent
  m_seekEvent.Set();
  CThread::StopThread(bWait);
}

std::string CFileCache::GetContent()
{
  if (!m_source.GetImplemenation())
    return IFile::GetContent();

  return m_source.GetImplemenation()->GetContent();
}

std::string CFileCache::GetContentCharset(void)
{
  IFile* impl = m_source.GetImplemenation();
  if (!impl)
    return IFile::GetContentCharset();

  return impl->GetContentCharset();
}

int CFileCache::IoControl(EIoControl request, void* param)
{
  if (request == IOCTRL_CACHE_STATUS)
  {
    SCacheStatus* status = (SCacheStatus*)param;
    status->forward = m_pCache->WaitForData(0, 0);
    status->maxrate = m_writeRate;
    status->currate = m_writeRateActual;
    status->full    = m_cacheFull;
    return 0;
  }

  if (request == IOCTRL_CACHE_SETRATE)
  {
    m_writeRate = *(unsigned*)param;
    return 0;
  }

  if (request == IOCTRL_SEEK_POSSIBLE)
    return m_seekPossible;

  return -1;
}
