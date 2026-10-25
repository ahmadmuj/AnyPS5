#include "prx/libSceLibreSsl/include/Api.hpp"
#include "prx/libc/include/ApplicationHeap.hpp"
#include "prx/libc/include/general/VabiMacros.hpp"
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <stdexcept>
#include <vector>

struct TestBignum {
    std::uint64_t* d;
    int top;
    int dmax;
    int neg;
    int flags;
};

static constexpr int Malloced = 0x01;
static constexpr int StaticData = 0x02;
static constexpr int ConstTime = 0x04;
static constexpr int MaxWords = INT_MAX / (4 * 64);

static void Require(bool value, const char* what) {
    if (value) return;
    std::fprintf(stderr, "failed: %s\n", what);
    std::abort();
}

struct Freed {
    void* pointer;
    std::size_t bytes;
    bool wiped;
};

static std::map<void*, std::size_t> live;
static std::vector<Freed> freed;
static int allocations;

static void* APS5_VABI Allocate(std::size_t bytes) {
    void* pointer = std::malloc(bytes ? bytes : 1);
    Require(pointer != nullptr, "test heap allocation");
    live[pointer] = bytes;
    ++allocations;
    return pointer;
}

static void APS5_VABI Release(void* pointer) {
    if (!pointer) return;
    const auto block = live.find(pointer);
    Require(block != live.end(), "free of a block from the guest heap");
    bool wiped = true;
    for (std::size_t index = 0; index < block->second; ++index) wiped = wiped && static_cast<unsigned char*>(pointer)[index] == 0;
    freed.push_back({pointer, block->second, wiped});
    live.erase(block);
    std::free(pointer);
}

static void* APS5_VABI AllocateZeroed(std::size_t, std::size_t) {
    Require(false, "guest calloc is not used");
    return nullptr;
}

static void* APS5_VABI Reallocate(void*, std::size_t) {
    Require(false, "guest realloc is not used");
    return nullptr;
}

static void* APS5_VABI Align(std::size_t, std::size_t) {
    Require(false, "guest memalign is not used");
    return nullptr;
}

static void* APS5_VABI Realign(void*, std::size_t, std::size_t) {
    Require(false, "guest reallocalign is not used");
    return nullptr;
}

static int APS5_VABI PosixAlign(void**, std::size_t, std::size_t) {
    Require(false, "guest posix_memalign is not used");
    return 0;
}

static void InitializeHeap() {
    void* const api[10] {reinterpret_cast<void*>(Allocate), reinterpret_cast<void*>(Release), reinterpret_cast<void*>(AllocateZeroed),
        reinterpret_cast<void*>(Reallocate), reinterpret_cast<void*>(Align), reinterpret_cast<void*>(Realign), reinterpret_cast<void*>(PosixAlign)};
    ApplicationHeapRegister_nid_no_patch(api);
}

static bool Live(const void* pointer, std::size_t bytes) {
    const auto block = live.find(const_cast<void*>(pointer));
    return block != live.end() && block->second == bytes;
}

static bool FreedWiped(const void* pointer, std::size_t bytes) {
    for (const Freed& entry : freed) {
        if (entry.pointer == pointer) return entry.bytes == bytes && entry.wiped;
    }
    return false;
}

template<typename TAction> static void RequireThrows(TAction action, const char* what) {
    try { action(); } catch (const std::exception&) { return; }
    Require(false, what);
}

static const TestBignum* Stored(const EcKey* key) {
    return static_cast<const TestBignum*>(EC_KEY_get0_private_key_nid_postfix(key));
}

static void RequireCopy(const EcKey* key, const TestBignum& source, int top, int neg, const std::uint64_t* words, const char* what) {
    const TestBignum* stored = Stored(key);
    Require(stored != nullptr && stored != &source, what);
    Require(stored->top == top && stored->dmax == top && stored->neg == neg && stored->flags == Malloced, what);
    if (top == 0) {
        Require(stored->d == nullptr, what);
        return;
    }
    Require(stored->d != nullptr && stored->d != source.d, what);
    for (int word = 0; word < top; ++word) Require(stored->d[word] == words[word], what);
}

static void CheckNewKeys() {
    EcKey* key = EC_KEY_new_nid_postfix();
    Require(Stored(key) == nullptr, "EC_KEY_new has no private key");
    EC_KEY_free_nid_postfix(key);
    key = EC_KEY_new_by_curve_name_nid_postfix(415);
    Require(Stored(key) == nullptr, "EC_KEY_new_by_curve_name has no private key");
    EC_KEY_free_nid_postfix(key);
}

static void CheckCopy() {
    std::uint64_t words[] = {0x1122334455667788, 0x99aabbccddeeff00, 0x0102030405060708};
    const std::uint64_t expected[] = {0x1122334455667788, 0x99aabbccddeeff00, 0x0102030405060708};
    TestBignum source{words, 3, 3, 0, 0};
    EcKey* key = EC_KEY_new_by_curve_name_nid_postfix(415);
    Require(EC_KEY_set_private_key_nid_postfix(key, &source) == 1, "EC_KEY_set_private_key");
    RequireCopy(key, source, 3, 0, expected, "a copy of three words");
    words[0] = 0;
    words[2] = 0;
    source.top = 1;
    RequireCopy(key, source, 3, 0, expected, "the copy keeps its words after the source changes");
    EC_KEY_free_nid_postfix(key);
}

static void CheckCopiedFields() {
    std::uint64_t words[] = {0xfedcba9876543210, 0x5, 0xdead, 0xbeef, 0xcafe};
    const std::uint64_t expected[] = {0xfedcba9876543210, 0x5};
    TestBignum source{words, 2, 5, 1, StaticData | ConstTime};
    EcKey* key = EC_KEY_new_nid_postfix();
    Require(EC_KEY_set_private_key_nid_postfix(key, &source) == 1, "EC_KEY_set_private_key without a group");
    RequireCopy(key, source, 2, 1, expected, "a copy has dmax equal to top, the sign and only BN_FLG_MALLOCED");
    EC_KEY_free_nid_postfix(key);
}

static void CheckZero() {
    std::uint64_t words[] = {7, 8, 9, 10};
    TestBignum withWords{words, 0, 4, 1, 0};
    EcKey* key = EC_KEY_new_by_curve_name_nid_postfix(415);
    Require(EC_KEY_set_private_key_nid_postfix(key, &withWords) == 1, "EC_KEY_set_private_key of zero with words");
    RequireCopy(key, withWords, 0, 1, nullptr, "a zero copy has no words and keeps its sign");
    TestBignum withoutWords{nullptr, 0, 0, 0, 0};
    Require(EC_KEY_set_private_key_nid_postfix(key, &withoutWords) == 1, "EC_KEY_set_private_key of zero without words");
    RequireCopy(key, withoutWords, 0, 0, nullptr, "a zero copy without words");
    EC_KEY_free_nid_postfix(key);
}

static void CheckReplaceAndClear() {
    std::uint64_t first[] = {0x11};
    std::uint64_t second[] = {0x2222, 0x3333};
    TestBignum one{first, 1, 1, 0, 0};
    TestBignum two{second, 2, 2, 0, 0};
    EcKey* key = EC_KEY_new_by_curve_name_nid_postfix(415);
    Require(EC_KEY_set_private_key_nid_postfix(key, &one) == 1, "EC_KEY_set_private_key of a first key");
    Require(EC_KEY_set_private_key_nid_postfix(key, &two) == 1, "EC_KEY_set_private_key replacing a key");
    RequireCopy(key, two, 2, 0, second, "the replaced private key");
    Require(EC_KEY_set_private_key_nid_postfix(key, nullptr) == 0, "EC_KEY_set_private_key with a null key");
    Require(Stored(key) == nullptr, "a null key drops the previous one");
    Require(EC_KEY_set_private_key_nid_postfix(key, nullptr) == 0, "EC_KEY_set_private_key with a null key and no key");
    Require(Stored(key) == nullptr, "a null key leaves no key");
    EC_KEY_free_nid_postfix(key);
}

static void CheckOtherKey() {
    std::uint64_t words[] = {0xaaaa, 0xbbbb, 0xcccc};
    TestBignum source{words, 3, 3, 1, 0};
    EcKey* first = EC_KEY_new_by_curve_name_nid_postfix(415);
    EcKey* second = EC_KEY_new_by_curve_name_nid_postfix(715);
    Require(EC_KEY_set_private_key_nid_postfix(first, &source) == 1, "EC_KEY_set_private_key of the first key");
    const TestBignum* original = Stored(first);
    Require(EC_KEY_set_private_key_nid_postfix(second, original) == 1, "EC_KEY_set_private_key from another key");
    Require(Stored(second) != original, "the second key has its own copy");
    EC_KEY_free_nid_postfix(first);
    RequireCopy(second, source, 3, 1, words, "the copy outlives the other key");
    EC_KEY_free_nid_postfix(second);
}

static void CheckTooLong() {
    std::uint64_t words[] = {0x55};
    std::uint64_t small[] = {1, 2, 3, 4};
    TestBignum valid{words, 1, 1, 0, 0};
    TestBignum longWords{small, MaxWords + 1, 4, 0, 0};
    TestBignum longNull{nullptr, MaxWords + 1, 0, 0, 0};
    EcKey* key = EC_KEY_new_by_curve_name_nid_postfix(415);
    Require(EC_KEY_set_private_key_nid_postfix(key, &valid) == 1, "EC_KEY_set_private_key before a long key");
    Require(EC_KEY_set_private_key_nid_postfix(key, &longWords) == 0, "EC_KEY_set_private_key over the word limit");
    Require(Stored(key) == nullptr, "a key over the word limit drops the previous one");
    Require(EC_KEY_set_private_key_nid_postfix(key, &longNull) == 0, "EC_KEY_set_private_key over the word limit with null words");
    Require(Stored(key) == nullptr, "a key over the word limit with null words leaves no key");
    EC_KEY_free_nid_postfix(key);
}

static void CheckGroupChange() {
    std::uint64_t words[] = {0x1234, 0x5678};
    TestBignum source{words, 2, 2, 0, 0};
    EcKey* key = EC_KEY_new_by_curve_name_nid_postfix(415);
    EcGroup* group = EC_GROUP_new_by_curve_name_nid_postfix(715);
    Require(EC_KEY_set_private_key_nid_postfix(key, &source) == 1, "EC_KEY_set_private_key before EC_KEY_set_group");
    const TestBignum* stored = Stored(key);
    Require(EC_KEY_set_group_nid_postfix(key, group) == 1, "EC_KEY_set_group with a private key");
    Require(Stored(key) == stored, "EC_KEY_set_group keeps the private key");
    RequireCopy(key, source, 2, 0, words, "the private key after EC_KEY_set_group");
    Require(EC_KEY_set_group_nid_postfix(key, nullptr) == 0, "EC_KEY_set_group with a null group");
    Require(Stored(key) == stored, "a null group keeps the private key");
    EC_GROUP_free_nid_postfix(group);
    EC_KEY_free_nid_postfix(key);
}

static void CheckGuestHeap() {
    std::uint64_t first[] = {0x1111, 0x2222, 0x3333};
    std::uint64_t second[] = {0x4444};
    TestBignum three{first, 3, 3, 0, 0};
    TestBignum one{second, 1, 1, 0, 0};
    TestBignum zero{nullptr, 0, 0, 0, 0};
    EcKey* key = EC_KEY_new_by_curve_name_nid_postfix(415);
    allocations = 0;
    freed.clear();
    Require(EC_KEY_set_private_key_nid_postfix(key, &three) == 1, "EC_KEY_set_private_key on the test heap");
    const TestBignum* stored = Stored(key);
    Require(allocations == 2 && freed.empty(), "a copy of three words takes two guest allocations");
    Require(Live(stored, sizeof(TestBignum)) && Live(stored->d, 3 * sizeof(std::uint64_t)), "the copy and its words come from the guest heap");
    const void* oldNumber = stored;
    const void* oldWords = stored->d;
    Require(EC_KEY_set_private_key_nid_postfix(key, &one) == 1, "EC_KEY_set_private_key replacing a key on the test heap");
    Require(allocations == 4 && freed.size() == 2, "replacing a key frees the old copy and its words");
    Require(FreedWiped(oldWords, 3 * sizeof(std::uint64_t)) && FreedWiped(oldNumber, sizeof(TestBignum)), "the old words and BIGNUM are cleared before they are freed");
    Require(EC_KEY_set_private_key_nid_postfix(key, &zero) == 1, "EC_KEY_set_private_key of zero on the test heap");
    Require(allocations == 5 && freed.size() == 4, "a zero copy takes one guest allocation");
    Require(Live(Stored(key), sizeof(TestBignum)), "the zero copy comes from the guest heap");
    Require(EC_KEY_set_private_key_nid_postfix(key, nullptr) == 0, "EC_KEY_set_private_key with a null key on the test heap");
    Require(allocations == 5 && freed.size() == 5, "a null key frees the old copy");
    Require(EC_KEY_set_private_key_nid_postfix(key, &three) == 1, "EC_KEY_set_private_key before EC_KEY_free");
    stored = Stored(key);
    oldNumber = stored;
    oldWords = stored->d;
    freed.clear();
    EC_KEY_free_nid_postfix(key);
    Require(freed.size() == 2 && FreedWiped(oldWords, 3 * sizeof(std::uint64_t)) && FreedWiped(oldNumber, sizeof(TestBignum)), "EC_KEY_free clears and frees the private key");
    Require(live.empty(), "no guest block is left");
}

static void CheckThrows() {
    std::uint64_t words[] = {0x99, 0x77};
    TestBignum valid{words, 2, 2, 0, 0};
    TestBignum negative{words, -1, 2, 0, 0};
    TestBignum nullWords{nullptr, 2, 2, 0, 0};
    TestBignum nullAtLimit{nullptr, MaxWords, 0, 0, 0};
    RequireThrows([] { EC_KEY_get0_private_key_nid_postfix(nullptr); }, "EC_KEY_get0_private_key of a null key");
    RequireThrows([&] { EC_KEY_set_private_key_nid_postfix(nullptr, &valid); }, "EC_KEY_set_private_key of a null key");
    EcKey* key = EC_KEY_new_by_curve_name_nid_postfix(415);
    Require(EC_KEY_set_private_key_nid_postfix(key, &valid) == 1, "EC_KEY_set_private_key before the throwing calls");
    const TestBignum* stored = Stored(key);
    RequireThrows([&] { EC_KEY_set_private_key_nid_postfix(key, stored); }, "EC_KEY_set_private_key with the key's own private key");
    TestBignum sharedWords{stored->d, 2, 2, 0, 0};
    RequireThrows([&] { EC_KEY_set_private_key_nid_postfix(key, &sharedWords); }, "EC_KEY_set_private_key with the words of the key's own private key");
    TestBignum lastWord{stored->d + 1, 1, 1, 0, 0};
    RequireThrows([&] { EC_KEY_set_private_key_nid_postfix(key, &lastWord); }, "EC_KEY_set_private_key with a word of the key's own private key");
    auto* writable = const_cast<TestBignum*>(stored);
    writable->top = MaxWords + 1;
    RequireThrows([&] { EC_KEY_set_private_key_nid_postfix(key, stored); }, "EC_KEY_set_private_key with the key's own private key over the word limit");
    writable->top = 2;
    TestBignum sharedZero{stored->d + 1, 0, 2, 0, 0};
    RequireThrows([&] { EC_KEY_set_private_key_nid_postfix(key, &negative); }, "EC_KEY_set_private_key with a negative word count");
    RequireThrows([&] { EC_KEY_set_private_key_nid_postfix(key, &nullWords); }, "EC_KEY_set_private_key with null words");
    RequireThrows([&] { EC_KEY_set_private_key_nid_postfix(key, &nullAtLimit); }, "EC_KEY_set_private_key with null words at the word limit");
    Require(Stored(key) == stored, "a throwing call keeps the private key");
    RequireCopy(key, valid, 2, 0, words, "the private key after the throwing calls");
    Require(EC_KEY_set_private_key_nid_postfix(key, &sharedZero) == 1, "EC_KEY_set_private_key of zero over the key's own words");
    RequireCopy(key, sharedZero, 0, 0, nullptr, "a zero copy reads no words");
    EC_KEY_free_nid_postfix(key);
}

int main() {
    InitializeHeap();
    CheckNewKeys();
    CheckCopy();
    CheckCopiedFields();
    CheckZero();
    CheckReplaceAndClear();
    CheckOtherKey();
    CheckTooLong();
    CheckGroupChange();
    CheckGuestHeap();
    CheckThrows();
    return 0;
}
