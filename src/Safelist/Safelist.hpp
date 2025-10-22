#pragma once

#include "RS2Tools.hpp"

#include <boost/asio/awaitable.hpp>

namespace asio = boost::asio;

namespace RS2::Safelist
{

// TODO:
asio::awaitable<void> DumpSafelist(/* stream? */);

} // namespace RS2::Safelist
