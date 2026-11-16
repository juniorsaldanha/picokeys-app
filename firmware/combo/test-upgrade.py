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
