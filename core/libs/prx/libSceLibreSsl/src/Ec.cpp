#include "prx/libSceLibreSsl/include/Api.hpp"
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include "prx/libSceLibreSsl/include/Ec.hpp"
#include "prx/libc/include/Api.hpp"
#include "prx/libc/include/General.hpp"
#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"

EcGroup::EcGroup(const NamedCurve& named) : curve(named) {
    mbedtls_ecp_group_init(&group);
    if (mbedtls_ecp_group_load(&group, named.id) != 0) {
        mbedtls_ecp_group_free(&group);
        throw std::runtime_error("EC_GROUP: mbedtls failed to load curve " + std::to_string(named.nid));
    }
}

EcGroup::~EcGroup() {
    mbedtls_ecp_group_free(&group);
}

struct EcBignum {
    std::uint64_t* d;
    int top;
    int dmax;
    int neg;
    int flags;
};

static_assert(sizeof(EcBignum) == 24);
static_assert(offsetof(EcBignum, top) == 8);

namespace {
constexpr NamedCurve NamedCurves[] = {
    {409, MBEDTLS_ECP_DP_SECP192R1},
    {415, MBEDTLS_ECP_DP_SECP256R1},
    {711, MBEDTLS_ECP_DP_SECP192K1},
    {712, MBEDTLS_ECP_DP_SECP224K1},
    {713, MBEDTLS_ECP_DP_SECP224R1},
    {714, MBEDTLS_ECP_DP_SECP256K1},
    {715, MBEDTLS_ECP_DP_SECP384R1},
    {716, MBEDTLS_ECP_DP_SECP521R1},
    {928, MBEDTLS_ECP_DP_BP256R1},
    {932, MBEDTLS_ECP_DP_BP384R1},
    {934, MBEDTLS_ECP_DP_BP512R1},
};

constexpr std::pair<int, int> CurvesMissingFromMbedtls[] = {
    {410, 414}, {684, 690}, {693, 696}, {699, 710}, {717, 745}, {749, 750},
    {839, 844}, {922, 927}, {929, 931}, {933, 933}, {935, 936}, {943, 944},
};

std::unique_ptr<EcGroup> NewGroup(int nid) {
    for (const NamedCurve& curve : NamedCurves) {
        if (curve.nid == nid) return std::make_unique<EcGroup>(curve);
    }
    for (const auto& [first, last] : CurvesMissingFromMbedtls) {
        if (nid >= first && nid <= last) NotImplemented_nid_no_patch("EC_GROUP_new_by_curve_name: a LibreSSL curve that mbedtls does not provide");
    }
    return nullptr;
}

constexpr int BignumFlagMalloced = 0x01;
constexpr int BignumFlagStaticData = 0x02;
constexpr int BignumMaxWords = INT_MAX / (4 * 64);

void Wipe(void* data, std::size_t size) {
    auto* bytes = static_cast<volatile unsigned char*>(data);
    for (std::size_t index = 0; index < size; ++index) bytes[index] = 0;
}

bool SharesWords(const EcBignum& source, const EcBignum* stored) {
    if (!stored || source.top == 0) return false;
    const auto sourceStart = reinterpret_cast<std::uintptr_t>(source.d);
    const auto storedStart = reinterpret_cast<std::uintptr_t>(stored->d);
    const std::uintptr_t sourceEnd = sourceStart + static_cast<std::uintptr_t>(source.top) * sizeof(std::uint64_t);
    const std::uintptr_t storedEnd = storedStart + static_cast<std::uintptr_t>(stored->dmax) * sizeof(std::uint64_t);
    return sourceStart < storedEnd && storedStart < sourceEnd;
}

std::unique_ptr<EcBignum, EcBignumDeleter> DuplicateBignum(const EcBignum& source) {
    std::unique_ptr<EcBignum, EcBignumDeleter> number(static_cast<EcBignum*>(malloc_nid_postfix(sizeof(EcBignum))));
    if (!number) return nullptr;
    *number = {nullptr, 0, 0, 0, BignumFlagMalloced};
    if (source.top > 0) {
        const std::size_t words = static_cast<std::size_t>(source.top);
        number->d = static_cast<std::uint64_t*>(malloc_nid_postfix(words * sizeof(std::uint64_t)));
        if (!number->d) return nullptr;
        number->dmax = source.top;
        std::memcpy(number->d, source.d, words * sizeof(std::uint64_t));
    }
    number->top = source.top;
    number->neg = source.neg;
    return number;
}

int DerLengthSize(int length) {
    int size = 1;
    if (length > 127) {
        for (; length > 0; length >>= 8) ++size;
    }
    return size;
}

}

void EcBignumDeleter::operator()(EcBignum* number) const {
    if (number->d && !(number->flags & BignumFlagStaticData)) {
        Wipe(number->d, static_cast<std::size_t>(number->dmax) * sizeof(number->d[0]));
        free_nid_postfix(number->d);
    }
    const bool allocated = number->flags & BignumFlagMalloced;
    Wipe(number, sizeof(EcBignum));
    if (allocated) free_nid_postfix(number);
}

extern "C" {

EcGroup* APS5_VABI EC_GROUP_new_by_curve_name_nid_postfix(int nid) {
    return NewGroup(nid).release();
}

void APS5_VABI EC_GROUP_free_nid_postfix(EcGroup* group) {
    delete group;
}

int APS5_VABI EC_GROUP_get_degree_nid_postfix(const EcGroup* group) {
    if (group == nullptr) APS5_INVALID_ARG_EX;
    return static_cast<int>(group->group.pbits);
}

EcKey* APS5_VABI EC_KEY_new_nid_postfix(void) {
    return new EcKey;
}

EcKey* APS5_VABI EC_KEY_new_by_curve_name_nid_postfix(int nid) {
    std::unique_ptr<EcGroup> group = NewGroup(nid);
    if (!group) return nullptr;
    return new EcKey{std::move(group)};
}

void APS5_VABI EC_KEY_free_nid_postfix(EcKey* key) {
    delete key;
}

const EcGroup* APS5_VABI EC_KEY_get0_group_nid_postfix(const EcKey* key) {
    if (key == nullptr) APS5_INVALID_ARG_EX;
    return key->group.get();
}

int APS5_VABI EC_KEY_set_group_nid_postfix(EcKey* key, const EcGroup* group) {
    if (key == nullptr) APS5_INVALID_ARG_EX;
    key->group = group ? std::make_unique<EcGroup>(group->curve) : nullptr;
    return key->group ? 1 : 0;
}

const void* APS5_VABI EC_KEY_get0_private_key_nid_postfix(const EcKey* key) {
    if (key == nullptr) APS5_INVALID_ARG_EX;
    return key->privateKey.get();
}

int APS5_VABI EC_KEY_set_private_key_nid_postfix(EcKey* key, const void* privateKey) {
    if (key == nullptr) APS5_INVALID_ARG_EX;
    const auto* source = static_cast<const EcBignum*>(privateKey);
    if (source != nullptr && source == key->privateKey.get()) throw std::invalid_argument("EC_KEY_set_private_key: the key's own private key, which LibreSSL frees before copying");
    if (source != nullptr && source->top <= BignumMaxWords) {
        if (source->top < 0) throw std::invalid_argument("EC_KEY_set_private_key: private key word count " + std::to_string(source->top));
        if (source->top > 0 && !source->d) throw std::invalid_argument("EC_KEY_set_private_key: null private key words");
        if (SharesWords(*source, key->privateKey.get())) throw std::invalid_argument("EC_KEY_set_private_key: the words of the key's own private key, which LibreSSL frees before copying");
    }
    key->privateKey.reset();
    if (source == nullptr || source->top > BignumMaxWords) return 0;
    key->privateKey = DuplicateBignum(*source);
    return key->privateKey ? 1 : 0;
}

int APS5_VABI ECDSA_size_nid_postfix(const EcKey* key) {
    if (key == nullptr || !key->group) return 0;
    const int orderBytes = static_cast<int>((mbedtls_mpi_bitlen(&key->group->group.N) + 7) / 8);
    const int integerSize = 1 + DerLengthSize(orderBytes + 1) + orderBytes + 1;
    return 1 + DerLengthSize(2 * integerSize) + 2 * integerSize;
}

}
