// Operating system entropy. Fails hard when no trustworthy source exists.
#pragma once

#include <cstddef>

namespace aurora {

void random_bytes(void* buffer, size_t length);

}  // namespace aurora
