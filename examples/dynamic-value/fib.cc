/* -*-mode:c++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#include <iostream>
#include <string>
#include <fstream>
#include <cstdlib>

#include "thunk/ggutils.hh"
#include "thunk/thunk.hh"
#include "thunk/thunk_writer.hh"
#include "util/exception.hh"
#include "util/path.hh"
#include "util/util.hh"

using namespace std;
using namespace gg;
using namespace gg::thunk;

int main( int argc, char * argv[] )
{
  try {
    if ( argc != 2 ) {
      cerr << "usage: fib <N>" << endl;
      return EXIT_FAILURE;
    }

    ifstream in( argv[ 1 ] );
    long long N;
    in >> N;
    if ( in.fail() or in.bad() ) {
      cerr << "Could not read from file: " << argv[ 1 ] << endl;
      return EXIT_FAILURE;
    }

    if ( N < 0 ) {
      cerr << argv[ 0 ] << " doesn't accept negative inputs" << endl;
      return EXIT_FAILURE;
    }

    if ( N < 2 ) {
      /* in this case, we just return the value and our job is done */
      roost::atomic_create( to_string(N), "out" );
      roost::atomic_create( "", "left.thunk" );
      roost::atomic_create( "", "left.in" );
      roost::atomic_create( "", "right.thunk" );
      roost::atomic_create( "", "right.in" );
      return EXIT_SUCCESS;
    }

    const string fib_func_hash = safe_getenv( "FIB_FUNCTION_HASH" );
    const string add_func_hash = safe_getenv( "ADD_FUNCTION_HASH" );

    vector<string> envars = { "FIB_FUNCTION_HASH=" + fib_func_hash,
                              "ADD_FUNCTION_HASH=" + add_func_hash };

    roost::atomic_create( to_string( N - 1 ), "left.in" );
    roost::atomic_create( to_string( N - 2 ), "right.in" );

    const string left_in_hash = gg::hash::file_force( "left.in" );
    const string right_in_hash = gg::hash::file_force( "right.in" );

    const Thunk fib_left {
      { fib_func_hash,
        { "fib", thunk::data_placeholder( left_in_hash ) },
        envars },
      { { left_in_hash, "" } },
      { { fib_func_hash, "" } },
      { { "out" }, { "left.thunk" }, { "right.thunk" },
        { "left.in" }, { "right.in" } }
    };

    const Thunk fib_right {
      { fib_func_hash,
        { "fib", thunk::data_placeholder( right_in_hash ) },
        envars },
      { { right_in_hash, "" } },
      { { fib_func_hash, "" } },
      { { "out" }, { "left.thunk" }, { "right.thunk" },
        { "left.in" }, { "right.in" } }
    };

    const string fib_left_hash = ThunkWriter::write( fib_left, "left.thunk" );
    const string fib_right_hash = ThunkWriter::write( fib_right, "right.thunk" );

    const Thunk add_thunk {
      { add_func_hash, { "add",
                         thunk::data_placeholder( fib_left_hash ),
                         thunk::data_placeholder( fib_right_hash ) }, {} },
      { { fib_left_hash, "" }, { fib_right_hash, "" } },
      { { add_func_hash, "" } },
      { { "out" } }
    };

    ThunkWriter::write( add_thunk, "out" );
  }
  catch ( const exception &  e ) {
    print_exception( argv[ 0 ], e );
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
