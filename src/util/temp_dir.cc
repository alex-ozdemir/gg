/* -*-mode:c++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#include "temp_dir.hh"

#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <cassert>

#include "temp_file.hh"
#include "exception.hh"

using namespace std;

UniqueDirectory::UniqueDirectory( const string & dirname_template )
  : mutable_temp_dirname_( to_mutable( dirname_template + ".XXXXXX" ) ),
    owns_dir_( false )
{
  if ( mkdtemp( &mutable_temp_dirname_[ 0 ] ) == NULL ) {
    throw unix_error( "mkdtemp " + name() );
  }
}

/* unlike UniqueDirectory, a TempDirectory is deleted when object destroyed */
TempDirectory::~TempDirectory()
{
  remove();
}

void TempDirectory::remove()
{
  if ( owns_dir_ ) { return; }
  owns_dir_ = true;
  try {
    CheckSystemCall( "rmdir " + name(), rmdir( name().c_str() ) );
  }
  catch ( const exception & e ) {
    cerr << e.what() << endl;
  }
}

UniqueDirectory::UniqueDirectory( UniqueDirectory && other )
  : mutable_temp_dirname_( other.mutable_temp_dirname_ ),
    owns_dir_( false )
{
  other.owns_dir_ = true;
}

string UniqueDirectory::name( void ) const
{
  assert( mutable_temp_dirname_.size() > 1 );
  return string( mutable_temp_dirname_.begin(), mutable_temp_dirname_.end() - 1 );
}
