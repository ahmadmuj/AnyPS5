#pragma once

#include <memory>
#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"

struct NamedCurve {
    int nid;
    mbedtls_ecp_group_id id;
};

struct EcGroup {
    explicit EcGroup(const NamedCurve& named);
    ~EcGroup();

    EcGroup(const EcGroup&) = delete;
    EcGroup& operator=(const EcGroup&) = delete;

    const NamedCurve curve;
    mbedtls_ecp_group group;
};

struct EcPoint {
    explicit EcPoint(const NamedCurve& named);
    ~EcPoint();

    EcPoint(const EcPoint&) = delete;
    EcPoint& operator=(const EcPoint&) = delete;

    const NamedCurve curve;
    mbedtls_ecp_point point;
};

struct EcPrivateKey {
    explicit EcPrivateKey(const NamedCurve& named);
    ~EcPrivateKey();

    EcPrivateKey(const EcPrivateKey&) = delete;
    EcPrivateKey& operator=(const EcPrivateKey&) = delete;

    const NamedCurve curve;
    mbedtls_mpi value;
};

struct EcKey {
    std::unique_ptr<EcGroup> group;
    std::unique_ptr<EcPoint> publicKey;
    std::unique_ptr<EcPrivateKey> privateKey;
};
