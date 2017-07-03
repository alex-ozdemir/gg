/* -*-mode:c++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#ifndef SYSTEM_RUNNER_HH
#define SYSTEM_RUNNER_HH

#include <vector>
#include <string>
#include <functional>

int ezexec( const std::vector<std::string> & command,
            const std::vector<std::string> & environment,
            const bool use_environ = false,
            const bool path_search = false );

void run( const std::vector<std::string> & command,
          const std::vector<std::string> & environment,
          const bool use_environ = false,
          const bool path_search = false );

#endif /* SYSTEM_RUNNER_HH */
