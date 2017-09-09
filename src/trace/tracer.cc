/* -*-mode:c++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#include "tracer.hh"

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <signal.h>
#include <errno.h>
#include <cstring>
#include <sstream>
#include <exception>

#include "exception.hh"

using namespace std;

template <typename T> void zero( T & x ) { memset( &x, 0, sizeof( x ) ); }

TracerFlock::TracerFlock( const ProcessTracer::entry_type & before_entry_function,
                          const ProcessTracer::exit_type & after_exit_function )
  : before_entry_function_( before_entry_function ),
    after_exit_function_( after_exit_function )
{}

void TracerFlock::insert( const pid_t tracee_pid )
{
  if ( tracers_.count( tracee_pid ) != 0 ) {
    throw runtime_error( "bad attempt to insert pid " + to_string( tracee_pid ) );
  }

  tracers_.emplace( make_pair( tracee_pid, tracee_pid ) );
}

void TracerFlock::remove( const pid_t tracee_pid )
{
  if ( tracers_.count( tracee_pid ) != 1 ) {
    throw runtime_error( "bad attempt to remove pid " + to_string( tracee_pid ) );
  }

  tracers_.erase( tracee_pid );
}

void TracerFlock::loop_until_all_done()
{
  while ( not tracers_.empty() ) {
    siginfo_t infop;
    zero( infop );
    CheckSystemCall( "waitid", waitid( P_ALL, 0, &infop, WSTOPPED | WNOWAIT ) );

    if ( infop.si_signo != SIGCHLD ) {
      throw runtime_error( "waitid: unexpected value in siginfo_t si_signo field (not SIGCHLD)" );
    }

    const pid_t tracee_with_event = infop.si_pid;

    if ( tracers_.count( tracee_with_event ) == 0 ) {
      if ( infop.si_status == ( SIGTRAP | ( PTRACE_EVENT_EXEC << 8 ) ) ) {
        /* is it an exec event from a "back from the dead" thread? */
        /* see ptrace(2) "execve(2) under ptrace" for discussion */

        insert( tracee_with_event );
      } else if ( infop.si_status == SIGSTOP ) {
        /* is it a fresh new process? */

        insert( tracee_with_event );
      } else {
        throw runtime_error( "unexpected event from PID " + to_string( tracee_with_event ) );
      }
    }

    if ( tracers_.at( tracee_with_event ).handle_one_event( *this,
                                                            before_entry_function_,
                                                            after_exit_function_ ) ) {
      /* tracer is done and ready to be destructed */
      remove( tracee_with_event );
    }
  }
}

ProcessTracer::ProcessTracer( const pid_t tracee_pid )
  : tracee_pid_( tracee_pid )
{}

void ProcessTracer::set_ptrace_options() const
{
  /* set ptrace options to trace children of the tracee */
  CheckSystemCall( "ptrace(SETOPTIONS)", ptrace( PTRACE_SETOPTIONS, tracee_pid_, 0,
                                                 PTRACE_O_TRACESYSGOOD |
                                                 PTRACE_O_TRACEEXEC |
                                                 PTRACE_O_TRACEEXIT |
                                                 PTRACE_O_TRACEFORK |
                                                 PTRACE_O_TRACEVFORK |
                                                 PTRACE_O_TRACECLONE |
                                                 PTRACE_O_EXITKILL ) );
}

/* blocking wait on one process */
bool ProcessTracer::handle_one_event( TracerFlock & flock,
                               const entry_type & before_entry_function ,
                               const exit_type & after_exit_function )
{
  siginfo_t infop;
  zero( infop );
  CheckSystemCall( "waitid", waitid( P_PID, tracee_pid_, &infop, WSTOPPED | WNOHANG ) );

  if ( infop.si_pid == 0 ) {
    throw runtime_error( "PID " + to_string( tracee_pid_ ) + " was not waitable" );
  }

  if ( infop.si_pid != tracee_pid_ ) {
    throw runtime_error( "waitid: unexpected value in siginfo_t si_pid field" );
  }

  if ( infop.si_signo != SIGCHLD ) {
    throw runtime_error( "waitid: unexpected value in siginfo_t si_signo field (not SIGCHLD)" );
  }

  if ( infop.si_code != CLD_TRAPPED ) {
    throw runtime_error( "waitid: unexpected siginfo_t si_code" );
  }

  if ( infop.si_status == SIGSTOP ) {
    /* tell ptrace when we next want to hear from the tracee,
       if we haven't already */
    if ( options_set_ ) {
      throw runtime_error( "multiple SIGSTOPs on same traced process" );
    }

    set_ptrace_options();
    options_set_ = true;
  } else if ( (infop.si_status & 0xff) == SIGTRAP ) {
    const unsigned int ptrace_event = (infop.si_status & 0xff00) >> 8;

    switch ( ptrace_event ) {
    case PTRACE_EVENT_FORK:
    case PTRACE_EVENT_VFORK:
    case PTRACE_EVENT_CLONE:
      /* ignore these events; we will trace the process when it shows up with a SIGSTOP */
      break;

    case PTRACE_EVENT_EXIT:
      return true;
      break;

    case PTRACE_EVENT_EXEC:
      {
        /* get former thread ID */
        pid_t former_pid;
        CheckSystemCall( "ptrace(PTRACE_GETEVENTMSG)",
                         ptrace( PTRACE_GETEVENTMSG, tracee_pid_, nullptr, &former_pid ) );

        if ( former_pid != tracee_pid_ ) {
          flock.remove( former_pid );
        }
      }

      break;

    default:
      throw runtime_error( "unhandled ptrace event type: " + to_string( ptrace_event ) );
    }
  } else if ( infop.si_status == (SIGTRAP | 0x80) ) {
    if ( not info_.syscall_invocation.initialized() ) {
      /* syscall entry */
      errno = 0;
      const long syscall_no = ptrace( PTRACE_PEEKUSER, tracee_pid_, sizeof( long ) * ORIG_RAX );
      if ( errno ) { throw unix_error( "ptrace" ); }

      info_.syscall_invocation.initialize( tracee_pid_, syscall_no );
      before_entry_function( info_ );

      if ( info_.detach ) {
        /* set the process free */
        return true;
      }
    } else {
      /* syscall exit */
      errno = 0;
      long syscall_ret = ptrace( PTRACE_PEEKUSER, tracee_pid_, sizeof( long ) * RAX );
      if ( errno ) { throw unix_error( "ptrace" ); }

      info_.syscall_invocation->set_retval( syscall_ret );
      after_exit_function( info_ );
      info_.syscall_invocation.clear();
    }
  } else if ( infop.si_status > SIGRTMAX ) {
    cerr << "other ptrace event (status=" << infop.si_status << ")\n";
    throw runtime_error( "unexpected ptrace event " + to_string( infop.si_status ) );
  } else {
    /* received signal */

    /* start tracee again and let it run until it hits a system call */
    CheckSystemCall( "ptrace(SYSCALL)", ptrace( PTRACE_SYSCALL, tracee_pid_, nullptr, infop.si_status ) );
    return false;
  }

  /* start tracee again and let it run until it hits a system call */
  CheckSystemCall( "ptrace(SYSCALL)", ptrace( PTRACE_SYSCALL, tracee_pid_, nullptr, 0 ) );

  return false;
}

ProcessTracer::ProcessTracer( ProcessTracer && pt )
  : tracee_pid_( pt.tracee_pid_ ),
    options_set_( pt.options_set_ ),
    info_( pt.info_ )
{
  pt.tracee_pid_ = -1;
}

ProcessTracer::~ProcessTracer()
{
  if ( tracee_pid_ != -1 ) {
    CheckSystemCall( "ptrace(DETACH)", ptrace( PTRACE_DETACH, tracee_pid_, nullptr, 0 ) );
  }
}

Tracer::Tracer( function<int()> && child_procedure,
                const ProcessTracer::entry_type & before_entry_function,
                const ProcessTracer::exit_type & after_exit_function,
                function<void()> && preparation_procedure )
  :
    tp_( "traced",
      [preparation_procedure, child_procedure]()
      {
        preparation_procedure(),
        CheckSystemCall( "ptrace(TRACEME)", ptrace( PTRACE_TRACEME ) );
        raise( SIGSTOP );
        return child_procedure();
      }
    ), flock_( before_entry_function, after_exit_function )
{
  flock_.insert( tp_.pid() );
}

void Tracer::loop_until_done()
{
  flock_.loop_until_all_done();

  while ( not tp_.terminated() ) {
    tp_.wait();
  }

  if ( tp_.exit_status() ) {
    tp_.throw_exception();
  }
}
