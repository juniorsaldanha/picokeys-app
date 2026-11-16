import sys, pickle
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2, ClientPin
from fido2.ctap2.pin import PinProtocolV2
from fido2.utils import sha256
dev = next(CtapHidDevice.list_devices()); c = Ctap2(dev); cp = ClientPin(c, PinProtocolV2())
cdh = sha256(b"client data"); rp = {"id": "example.com", "name": "Example"}
if sys.argv[1] == "before":
    cp.set_pin("123456")
    tok = cp.get_pin_token("123456", ClientPin.PERMISSION.MAKE_CREDENTIAL, "example.com")
    att = c.make_credential(cdh, rp, {"id": b"user1", "name": "u"}, [{"type": "public-key", "alg": -7}],
                            options={"rk": True}, pin_uv_param=cp.protocol.authenticate(tok, cdh), pin_uv_protocol=2)
    print("made credential", att.auth_data.credential_data.credential_id.hex()[:16])
else:
    tok = cp.get_pin_token("123456", ClientPin.PERMISSION.GET_ASSERTION, "example.com")
    a = c.get_assertion("example.com", cdh, pin_uv_param=cp.protocol.authenticate(tok, cdh), pin_uv_protocol=2)
    print("assertion ok, user", a.user["id"], "creds", a.number_of_credentials)
    print("retries", cp.get_pin_retries()[0], "versions", c.info.versions, "aaguid", c.info.aaguid)
if sys.argv[1] == "mixed":
    # a passkey made after OpenPGP/PIV keys exist
    tok = cp.get_pin_token("123456", ClientPin.PERMISSION.MAKE_CREDENTIAL, "second.example")
    rp2 = {"id": "second.example", "name": "Second"}
    c.make_credential(cdh, rp2, {"id": b"user2", "name": "v"}, [{"type": "public-key", "alg": -7}],
                      options={"rk": True}, pin_uv_param=cp.protocol.authenticate(tok, cdh), pin_uv_protocol=2)
if sys.argv[1] in ("before", "after", "mixed"):
    from fido2.ctap2 import CredentialManagement
    tok = cp.get_pin_token("123456", ClientPin.PERMISSION.CREDENTIAL_MGMT)
    cm = CredentialManagement(c, cp.protocol, tok)
    print(sys.argv[1], "metadata", cm.get_metadata())
    rps = cm.enumerate_rps()
    for rp in rps:
        print(" rp", rp[CredentialManagement.RESULT.RP])
        for cr in cm.enumerate_creds(rp[CredentialManagement.RESULT.RP_ID_HASH]):
            print("   user", cr[CredentialManagement.RESULT.USER])
    ids = [rp[CredentialManagement.RESULT.RP]["id"] for rp in rps]
    want = ["example.com", "second.example"] if sys.argv[1] == "mixed" else ["example.com"]
    assert sorted(ids) == want, f"passkey list broken: {ids!r}"
    print(sys.argv[1], "passkey list OK")
