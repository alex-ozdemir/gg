/* -*-mode:c++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstdlib>
#include <fcntl.h>

#include <cryptopp/base64.h>
#include <cryptopp/sha.h>
#include <cryptopp/files.h>

#include "util/exception.hh"
#include "util/file_descriptor.hh"

using namespace std;
using namespace CryptoPP;

void usage( const char * argv0 )
{
  cerr << argv0 << " FILENAME" << endl;
}

int main( int argc, char * argv[] )
{
  string path;
  try {
    if ( argc <= 0 ) {
      abort();
    }

    if ( argc != 2 ) {
      usage( argv[ 0 ] );
      return EXIT_FAILURE;
    }

    path = argv[1];

  }
  catch ( const exception &  e ) {
    print_exception( argv[ 0 ], e );
    return EXIT_FAILURE;
  }
  ifstream in(path);
  std::ostringstream buf;
  buf << in.rdbuf(); 
  string instr = buf.str();
  SHA256 hash_function;
  string out;
  cout << "Bytes " << instr.length() << endl;
  StringSource( instr, true, new HashFilter( hash_function, new Base64URLEncoder( new StringSink ( out ), false)));
  cout << out << endl;

  return EXIT_SUCCESS;
}
