#pragma once

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
#  define WINDOWS 1
#  define WIN32_LEAN_AND_MEAN
#  define VC_EXTRALEAN
#  include <SDKDDKVer.h> // Silence "Please define _WIN32_WINNT or _WIN32_WINDOWS appropriately".
#  include <windows.h>
#else
#  define WINDOWS 0
#endif

#if WINDOWS
#define WIN_MAYBE_CONSTEXPR const
#else
#define WIN_MAYBE_CONSTEXPR constexpr
#endif

#include "Crypto/Crypto.hpp"
#include "Safelist/Safelist.hpp"
