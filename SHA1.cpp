#include "SHA1.h"

#include <cstring>
#include <utility>

namespace
{
	template<std::uint32_t count>
	constexpr inline std::uint32_t rotl32(std::uint32_t value) noexcept
	{
		return value << count | value >> (32 - count);
	}

	template <typename T>
	T SwapEndian(T src) noexcept
	{
		for (auto ndx{ 0 }; ndx < sizeof (T) / 2; ++ndx)
		{
			std::swap(((char *)(&src))[sizeof (T) - ndx - 1], ((char *)(&src))[ndx]);
		}

		return src;
	}

	constexpr std::uint32_t init[]{ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };

	enum { A = 0, B, C, D, E };
}	// anonymous namespace

void SHA1(const char *p, std::uint64_t size, std::uint32_t res[5])
{
	std::memcpy(res, init, sizeof (init));

	std::uint32_t w[80];
	char tail[128]{ };

	*(std::uint64_t *)(tail + 64 + 56) = SwapEndian(size * 8);
	auto tail_size{ 1 };

	auto count{ size / 64 };
	size -= count * 64;
	const char *p1{ p + size };

	if (size > 0)
		std::memcpy(tail, p1, size);
	*(unsigned char *)(tail + size) = 0x80;

	if (size < 56)
	{
		*(std::uint64_t *)(tail + 56) = *(std::uint64_t *)(tail + 64 + 56);
		tail_size = 0;
	}

	std::uint32_t data[5];

	auto func = [&data](std::uint32_t kfw) noexcept
	{
		const std::uint32_t temp{ rotl32<5>(data[A]) + kfw + data[E] };
		data[E] = data[D];
		data[D] = data[C];
		data[C] = rotl32<30>(data[B]);
		data[B] = data[A];
		data[A] = temp;
	};

	do
	{
		if (count == 0)
		{
			p = tail;
			count += tail_size;
			tail_size = 0;
		}

		auto ndx{ 0 };

		for ( ; ndx < 16; ++ndx)
		{
			w[ndx] = SwapEndian(*((std::uint32_t *)p));
			p += sizeof (std::uint32_t);
		}

		for ( ; ndx < 80; ++ndx)
			w[ndx] = rotl32<1>(w[ndx - 3] ^ w[ndx - 8] ^ w[ndx - 14] ^ w[ndx - 16]);


		std::memcpy(data, res, sizeof (data));

		ndx = 0;

		for ( ; ndx < 20; ++ndx)
		{
			constexpr std::uint32_t k{ 0x5A827999 };
			const auto f{ (data[B] & data[C]) | ((~data[B]) & data[D]) };

			func(k + f + w[ndx]);
		}

		for ( ; ndx < 40; ++ndx)
		{
			constexpr std::uint32_t k{ 0x6ED9EBA1 };
			const auto f{ data[B] ^ data[C] ^ data[D] };

			func(k + f + w[ndx]);
		}

		for ( ; ndx < 60; ++ndx)
		{
			constexpr std::uint32_t k{ 0x8F1BBCDC };
			const auto f{ (data[B] & data[C]) | (data[B] & data[D]) | (data[C] & data[D]) };

			func(k + f + w[ndx]);
		}

		for ( ; ndx < 80; ++ndx)
		{
			constexpr std::uint32_t k{ 0xCA62C1D6 };
			const auto f{ data[B] ^ data[C] ^ data[D] };

			func(k + f + w[ndx]);
		}

		for (ndx = 0; ndx < 5; ++ndx)
			res[ndx] += data[ndx];

		if (count == 0)
			break;
		--count;
	}
	while (true);
}
