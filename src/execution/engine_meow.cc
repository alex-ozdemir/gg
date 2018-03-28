/* -*-mode:c++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#include "engine_meow.hh"

#include <iostream>

using namespace std;
using namespace PollerShortNames;

MeowExecutionEngine::MeowExecutionEngine( const AWSCredentials & credentials,
                                          const std::string & region,
                                          const Address & listen_addr,
                                          ExecutionLoop & loop,
                                          SuccessCallbackFunc success_callback,
                                          FailureCallbackFunc failure_callback )
  : ExecutionEngine( success_callback, failure_callback ),
    credentials_( credentials ), region_( region ),
    aws_addr_( LambdaInvocationRequest::endpoint( region_ ), "https" ),
    listen_addr_( listen_addr ), listen_socket_()
{
  listen_socket_.set_blocking( false );
  listen_socket_.set_reuseaddr();
  listen_socket_.bind( listen_addr_ );
  listen_socket_.listen();

  loop.poller().add_action( Poller::Action( listen_socket_, Direction::In,
    [] () -> ResultType
    {
      cerr << "Incoming connection!" << endl;
      return ResultType::Continue;
    }
  ) );
}