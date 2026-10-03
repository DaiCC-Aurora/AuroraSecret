// Command line interface.
#pragma once

#include <string>
#include <vector>

namespace aurora {

// Runs the whole program. Returns the process exit code.
int run_cli(const std::vector<std::string>& arguments);

}  // namespace aurora
