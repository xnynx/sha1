#pragma once

#include <cstdint>

void SHA1(const char *p, ::std::uint64_t size, ::std::uint32_t res[5]);

int sha1digest(uint8_t *digest, char *hexdigest, const uint8_t *data, size_t databytes);
