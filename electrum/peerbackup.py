# Copyright (C) 2018 The Electrum developers
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import json
import io
import attr
from copy import deepcopy

from . import util
from .lnutil import LOCAL, REMOTE
from .lnutil import UpdateAddHtlc, ChannelType
from .lnmsg import PeerBackupWireSerializer
from .lnutil import BIP32Node, generate_keypair, LnKeyFamily
from .lnhtlc import LOG_TEMPLATE
from .crypto import sha256


# Note: we must reconstruct everything from 2 owners
#
#  A          B       Alice=client, Bob=server
#
#   is_remote=True (bob receives CS)  [about updates sent by client]
#    ---Up-->
#    ---CS-->         bob: receive_peerbackup(their_remote)     alice: get_our_signed_peerbackup(remote)
#    <--Rev--         alice: recv_rev()   bob: send_rev(). occurs after sig.
#
#
#   is_remote=False (bob receives rev) [it is about updates proposed by server]
#    <--Up---
#    <--CS---
#    ---Rev->         bob: receive_new_peerbackup(their_local)  alice: get_our_signed_peerbackup(local)


PEERBACKUP_VERSION = 0

def ctn_to_bytes(x):
    if x is None:
        x = -1
    return int.to_bytes(x, length=8, byteorder="big", signed=True)

def bytes_to_ctn(x):
    ctn = int.from_bytes(x, byteorder="big", signed=True)
    if ctn == -1:
        ctn = None
    return ctn


@attr.s
class HtlcUpdate:
    htlc_id = attr.ib(type=int)
    amount_msat = attr.ib(type=int)
    payment_hash = attr.ib(type=bytes)
    cltv_abs = attr.ib(type=int)
    timestamp = attr.ib(type=int)
    is_success = attr.ib(type=bool, default=False)
    local_ctn_in = attr.ib(type=int, default=None)
    local_ctn_out = attr.ib(type=int, default=None)
    remote_ctn_in = attr.ib(type=int, default=None)
    remote_ctn_out = attr.ib(type=int, default=None)

    def flip(self):
        a = self.local_ctn_in
        b = self.local_ctn_out
        self.local_ctn_in = self.remote_ctn_in
        self.local_ctn_out = self.remote_ctn_out
        self.remote_ctn_in = a
        self.remote_ctn_out = b

    def update_local(self, v):
        self.local_ctn_in = v.local_ctn_in
        self.local_ctn_out = v.local_ctn_out

    def update_remote(self, v):
        self.remote_ctn_in = v.remote_ctn_in
        self.remote_ctn_out = v.remote_ctn_out

    def to_json(self):
        return (
            self.htlc_id,
            self.amount_msat,
            self.payment_hash.hex(),
            self.cltv_abs,
            self.timestamp,
            self.is_success,
            self.local_ctn_in,
            self.local_ctn_out,
            self.remote_ctn_in,
            self.remote_ctn_out,
        )

    def to_bytes(self, proposer, owner=None, blank_timestamps=False):
        local_ctn_in = None if owner == REMOTE else self.local_ctn_in
        local_ctn_out = None if owner == REMOTE else self.local_ctn_out
        remote_ctn_in = None if owner == LOCAL else self.remote_ctn_in
        remote_ctn_out = None if owner == LOCAL else self.remote_ctn_out
        is_success = self.is_success
        if owner == LOCAL and self.local_ctn_out is None:
            is_success = False
        if owner == REMOTE and self.remote_ctn_out is None:
            is_success = False
        if local_ctn_in is None and remote_ctn_in is None:
            return
        r = b'\x00' if proposer==LOCAL else b'\x01'
        r += int.to_bytes(self.htlc_id, length=8, byteorder="big", signed=False)
        r += int.to_bytes(self.amount_msat, length=8, byteorder="big", signed=False)
        r += self.payment_hash
        r += int.to_bytes(self.cltv_abs, length=8, byteorder="big", signed=False)
        r += int.to_bytes(0 if blank_timestamps else self.timestamp, length=8, byteorder="big", signed=False)
        r += b'\x01' if self.is_success else b'\x00'
        r += ctn_to_bytes(local_ctn_in)
        r += ctn_to_bytes(local_ctn_out)
        r += ctn_to_bytes(remote_ctn_in)
        r += ctn_to_bytes(remote_ctn_out)
        assert len(r) == 98, len(r)
        return r

    @classmethod
    def from_bytes(cls, chunk:bytes):
        assert len(chunk) == 98, len(chunk)
        with io.BytesIO(bytes(chunk)) as s:
            proposer = LOCAL if s.read(1) == b'\x00' else REMOTE
            htlc_update = HtlcUpdate(
                htlc_id = int.from_bytes(s.read(8), byteorder="big"),
                amount_msat = int.from_bytes(s.read(8), byteorder="big"),
                payment_hash = s.read(32),
                cltv_abs = int.from_bytes(s.read(8), byteorder="big"),
                timestamp = int.from_bytes(s.read(8), byteorder="big"),
                is_success = bool(s.read(1) == b'\x01'),
                local_ctn_in = bytes_to_ctn(s.read(8)),
                local_ctn_out = bytes_to_ctn(s.read(8)),
                remote_ctn_in = bytes_to_ctn(s.read(8)),
                remote_ctn_out = bytes_to_ctn(s.read(8)),
            )
        return proposer, htlc_update

@attr.s
class FeeUpdateNotStored:
    rate = attr.ib(type=int)  # in sat/kw
    ctn_local = attr.ib(default=None, type=int)
    ctn_remote = attr.ib(default=None, type=int)

    def flip(self):
        a = self.ctn_local
        self.ctn_local = self.ctn_remote
        self.ctn_remote = a

    def to_json(self):
        return (self.rate, self.ctn_local, self.ctn_remote)

    def to_bytes(self, proposer, fee_update_id, owner):
        ctn_local = None if owner == REMOTE else self.ctn_local
        ctn_remote = None if owner == LOCAL else self.ctn_remote
        if ctn_remote is None and ctn_local is None:
            return
        r = b'\x00' if proposer==LOCAL else b'\x01'
        r += int.to_bytes(fee_update_id, length=8, byteorder="big", signed=False)
        r += int.to_bytes(self.rate, length=8, byteorder="big", signed=False)
        r += ctn_to_bytes(ctn_local)
        r += ctn_to_bytes(ctn_remote)
        assert len(r) == 33, len(r)
        return r

    @classmethod
    def from_bytes(cls, chunk:bytes):
        assert len(chunk) == 33
        with io.BytesIO(bytes(chunk)) as s:
            proposer = LOCAL if s.read(1) == b'\x00' else REMOTE
            fee_update_id = int.from_bytes(s.read(8), byteorder="big")
            fee_update = FeeUpdateNotStored(
                rate = int.from_bytes(s.read(8), byteorder="big"),
                ctn_local = bytes_to_ctn(s.read(8)),
                ctn_remote = bytes_to_ctn(s.read(8)),
            )
        return proposer, fee_update_id, fee_update

@attr.s
class PeerBackup:

    channel_id = attr.ib(default=None, type=str)
    node_id = attr.ib(default=None, type=str)
    channel_type = attr.ib(default=None, type=str)
    constraints = attr.ib(default=None, type=str)
    funding_outpoint = attr.ib(default=None, type=str)
    local_config = attr.ib(default=None, type=str)
    remote_config = attr.ib(default=None, type=str)
    local_ctn = attr.ib(default=None, type=str)
    remote_ctn = attr.ib(default=None, type=str)
    htlc_log = attr.ib(default=None, type=str)
    fee_updates_log = attr.ib(default=None, type=str)
    revocation_store = attr.ib(default=None, type=str)

    @classmethod
    def from_channel(cls, chan):
        # convert StoredDict to dict
        with chan.db_lock:
            state = json.loads(json.dumps(chan.storage, cls=util.MyEncoder))
        # remove private keys
        for key in ['delayed_basepoint', 'revocation_basepoint', 'multisig_key', 'htlc_basepoint']:
            state['local_config'][key].pop('privkey')
        # payment_basepoint: not always here, sure why.
        # see tests.regtest.TestLightningJIT.test_just_in_time
        state['local_config']['payment_basepoint'].pop('privkey', None)
        state['local_config'].pop('per_commitment_secret_seed')
        state['local_config'].pop('funding_locked_received')
        # encrypt seed in local_config
        channel_seed = bytes.fromhex(state['local_config'].pop('channel_seed'))
        encrypted_seed = chan.lnworker.encrypt_channel_seed(channel_seed)
        state['local_config']['encrypted_seed'] = encrypted_seed.hex()
        # convert log to a list of HtlcUpdate
        log = chan.hm.log
        htlc_log = {LOCAL:{}, REMOTE:{}}
        fee_updates_log = {LOCAL:{}, REMOTE:{}}
        for proposer in [LOCAL, REMOTE]:
            for htlc_id, add in log[proposer]['adds'].items():
                local_ctn_in = chan.hm.get_ctn_if_lower_than_latest(proposer, 'locked_in', htlc_id, LOCAL)
                local_ctn_settle = chan.hm.get_ctn_if_lower_than_latest(proposer, 'settles', htlc_id, LOCAL)
                local_ctn_fail = chan.hm.get_ctn_if_lower_than_latest(proposer, 'fails', htlc_id, LOCAL)
                remote_ctn_in = chan.hm.get_ctn_if_lower_than_latest(proposer, 'locked_in', htlc_id, REMOTE)
                remote_ctn_settle = chan.hm.get_ctn_if_lower_than_latest(proposer, 'settles', htlc_id, REMOTE)
                remote_ctn_fail = chan.hm.get_ctn_if_lower_than_latest(proposer, 'fails', htlc_id, REMOTE)
                if local_ctn_in is None and remote_ctn_in is None:
                    continue
                is_success = local_ctn_settle is not None or remote_ctn_settle is not None
                if is_success:
                    local_ctn_out = local_ctn_settle
                    remote_ctn_out = remote_ctn_settle
                else:
                    local_ctn_out = local_ctn_fail
                    remote_ctn_out = remote_ctn_fail
                htlc_update = HtlcUpdate(
                    amount_msat = add.amount_msat,
                    payment_hash = add.payment_hash,
                    cltv_abs = add.cltv_abs,
                    timestamp = add.timestamp,
                    htlc_id = add.htlc_id,
                    is_success = is_success,
                    local_ctn_in = local_ctn_in,
                    local_ctn_out = local_ctn_out,
                    remote_ctn_in = remote_ctn_in,
                    remote_ctn_out = remote_ctn_out,
                )
                htlc_log[proposer][htlc_id] = htlc_update
            for update_id, f in log[proposer]['fee_updates'].items():
                fee_update = FeeUpdateNotStored(
                    rate=f.rate,
                    ctn_local=f.ctn_local,
                    ctn_remote=f.ctn_remote,
                )
                assert (fee_update.ctn_local is not None or fee_update.ctn_remote is not None), fee_update
                fee_updates_log[proposer][update_id] = fee_update

        return PeerBackup(
            channel_id = state['channel_id'],
            node_id = state['node_id'],
            channel_type = state['channel_type'],
            constraints = state['constraints'],
            funding_outpoint = state['funding_outpoint'],
            local_config = state['local_config'],
            remote_config = state['remote_config'],
            local_ctn = state['log']['1']['ctn'],
            remote_ctn = state['log']['-1']['ctn'],
            htlc_log = htlc_log,
            fee_updates_log = fee_updates_log,
            revocation_store = state['revocation_store'],
        )

    def to_json(self):
        return {
            'channel_id': self.channel_id,
            'node_id': self.node_id,
            'channel_type': self.channel_type,
            'constraints': self.constraints,
            'funding_outpoint': self.funding_outpoint,
            'local_config': self.local_config,
            'remote_config': self.remote_config,
            'local_ctn': self.local_ctn,
            'remote_ctn': self.remote_ctn,
            'htlc_log': self.htlc_log,
            'fee_updates_log': self.fee_updates_log,
            'revocation_store': self.revocation_store,
        }

    @classmethod
    def convert_config_to_payload(self, remote_config, ctn):
        a = {
            'htlc_basepoint': bytes.fromhex(remote_config['htlc_basepoint']['pubkey']),
            'payment_basepoint': bytes.fromhex(remote_config['payment_basepoint']['pubkey']),
            'revocation_basepoint': bytes.fromhex(remote_config['revocation_basepoint']['pubkey']),
            'delayed_basepoint': bytes.fromhex(remote_config['delayed_basepoint']['pubkey']),
            'multisig_key': bytes.fromhex(remote_config['multisig_key']['pubkey']),
            'to_self_delay': remote_config['to_self_delay'],
            'dust_limit_satoshis': remote_config['dust_limit_sat'],
            'max_htlc_value_in_flight_msat': remote_config['max_htlc_value_in_flight_msat'],
            'reserve_sat': remote_config['reserve_sat'],
            'initial_msat': remote_config['initial_msat'],
            'htlc_minimum_msat': remote_config['htlc_minimum_msat'],
            'max_accepted_htlcs': remote_config['max_accepted_htlcs'],
            'upfront_shutdown_script': bytes.fromhex(remote_config['upfront_shutdown_script']),
            'announcement_node_sig': bytes.fromhex(remote_config['announcement_node_sig']) or bytes(64),
            'announcement_bitcoin_sig': bytes.fromhex(remote_config['announcement_bitcoin_sig']) or bytes(64),
        }
        b = {
            'ctn': ctn,
            'current_per_commitment_point': bytes.fromhex(remote_config['current_per_commitment_point']),
            'next_per_commitment_point': bytes.fromhex(remote_config['next_per_commitment_point']),
            'current_commitment_signature': bytes.fromhex(remote_config['current_commitment_signature']),
            'current_htlc_signatures': bytes.fromhex(remote_config['current_htlc_signatures'] or ''),
        }
        return a, b

    @classmethod
    def convert_payload_to_config(self, config, ctx):
        ctn = ctx['ctn']
        config2 = {
            'htlc_basepoint': {'pubkey': config['htlc_basepoint'].hex()},
            'payment_basepoint': {'pubkey': config['payment_basepoint'].hex()},
            'revocation_basepoint': {'pubkey': config['revocation_basepoint'].hex()},
            'delayed_basepoint': {'pubkey':config['delayed_basepoint'].hex()},
            'multisig_key': {'pubkey':config['multisig_key'].hex()},
            'to_self_delay': config['to_self_delay'],
            'dust_limit_sat': config['dust_limit_satoshis'],
            'max_htlc_value_in_flight_msat': config['max_htlc_value_in_flight_msat'],
            'reserve_sat': config['reserve_sat'],
            'initial_msat': config['initial_msat'],
            'htlc_minimum_msat': config['htlc_minimum_msat'],
            'max_accepted_htlcs': config['max_accepted_htlcs'],
            'upfront_shutdown_script': config['upfront_shutdown_script'].hex(),
            'current_per_commitment_point': ctx['current_per_commitment_point'].hex(),
            'next_per_commitment_point': ctx['next_per_commitment_point'].hex(),
            'current_commitment_signature': ctx['current_commitment_signature'].hex(),
            'current_htlc_signatures': ctx['current_htlc_signatures'].hex(),
        }
        announcement_node_sig = config['announcement_node_sig']
        announcement_bitcoin_sig = config['announcement_bitcoin_sig']
        if announcement_node_sig == bytes(64):
            announcement_node_sig = b''
        if announcement_bitcoin_sig == bytes(64):
            announcement_bitcoin_sig = b''
        config2['announcement_node_sig'] = announcement_node_sig.hex()
        config2['announcement_bitcoin_sig'] = announcement_bitcoin_sig.hex()
        return config2, ctn

    @classmethod
    def from_bytes(cls, peerbackup_bytes: bytes) -> 'PeerBackup':
        payload = PeerBackupWireSerializer.read_tlv_stream(
            fd=io.BytesIO(peerbackup_bytes),
            tlv_stream_name="payload")
        version = payload['version']['version']
        assert version == PEERBACKUP_VERSION
        state = {
            'channel_id': payload['channel_id']['channel_id'].hex(),
            'channel_type': ChannelType.from_bytes(payload['channel_type']['type'], byteorder='big'),
            'node_id': payload['node_id']['node_id'].hex(),
            'constraints': payload['constraints'],
            'funding_outpoint': {
                'txid': payload['funding_outpoint']['txid'].hex(),
                'output_index': payload['funding_outpoint']['output_index'],
            }
        }
        if 'revocation_store' in payload:
            buckets = {}
            buckets_bytes = payload['revocation_store']['buckets']
            while buckets_bytes:
                chunk = buckets_bytes[0:42]
                buckets_bytes = buckets_bytes[42:]
                with io.BytesIO(bytes(chunk)) as s:
                    key = int.from_bytes(s.read(2), byteorder="big")
                    _hash = s.read(32)
                    _index = int.from_bytes(s.read(8), byteorder="big")
                buckets[key] = (_hash.hex(), _index)

            state['revocation_store'] = {
                'index': payload['revocation_store']['index'],
                'buckets': buckets,
            }
        if 'remote_config' in payload:
            a, b = cls.convert_payload_to_config(payload['remote_config'], payload['remote_ctx'])
            state['remote_config'] = a
            state['remote_ctn'] = b
            state['remote_config']['encrypted_seed'] = None

        if 'local_config' in payload:
            a, b = cls.convert_payload_to_config(payload['local_config'], payload['local_ctx'])
            state['local_config'] = a
            state['local_ctn'] = b
            state['local_config']['encrypted_seed'] = payload['encrypted_seed']['seed'].hex()

        fee_updates_log_bytes = payload['fee_updates_log']['fee_updates_log']
        fee_updates_log = {LOCAL:{}, REMOTE:{}}
        while fee_updates_log_bytes:
            chunk = fee_updates_log_bytes[0:33]
            fee_updates_log_bytes = fee_updates_log_bytes[33:]
            proposer, fee_update_id, fee_update = FeeUpdateNotStored.from_bytes(chunk)
            fee_updates_log[proposer][fee_update_id] = fee_update
        state['fee_updates_log'] = fee_updates_log

        htlc_log_bytes = payload['htlc_log']['active_htlcs']
        htlc_log = {LOCAL:{}, REMOTE:{}}
        while htlc_log_bytes:
            chunk = htlc_log_bytes[0:98]
            htlc_log_bytes = htlc_log_bytes[98:]
            proposer, htlc_update = HtlcUpdate.from_bytes(chunk)
            htlc_log[proposer][htlc_update.htlc_id] = htlc_update
        state['htlc_log'] = htlc_log

        return PeerBackup(**state)

    def to_bytes(self, owner=None, blank_timestamps=False) -> bytes:
        htlc_log_bytes = b''
        htlc_history_hash = sha256(b'htlc_history')
        for proposer in [LOCAL, REMOTE]:
            for htlc_id, htlc_update in list(self.htlc_log[proposer].items()):
                _bytes = htlc_update.to_bytes(proposer, owner, blank_timestamps)
                if _bytes is None:
                    continue
                htlc_log_bytes += _bytes

        fee_updates_log_bytes = b''
        for proposer in [LOCAL, REMOTE]:
            for fee_update_id, fee_update in list(self.fee_updates_log[proposer].items()):
                _bytes = fee_update.to_bytes(proposer, fee_update_id, owner)
                if _bytes is None:
                    continue
                fee_updates_log_bytes += _bytes

        payload = {
            'version': {'version': PEERBACKUP_VERSION},
            'channel_id': {'channel_id': bytes.fromhex(self.channel_id)},
            'channel_type': {'type': ChannelType(self.channel_type).to_bytes_minimal()},
            'node_id': {'node_id': bytes.fromhex(self.node_id)},
            'htlc_log': {
                'htlc_history_hash': htlc_history_hash,
                'active_htlcs': htlc_log_bytes,
            },
            'fee_updates_log': {
                'fee_updates_log': fee_updates_log_bytes,
            },
            'constraints': self.constraints,
            'funding_outpoint': {
                'txid': bytes.fromhex(self.funding_outpoint['txid']),
                'output_index': self.funding_outpoint['output_index'],
            },
        }
        if owner != LOCAL:
            buckets_bytes = b''
            buckets = self.revocation_store['buckets']
            for k, v in sorted(buckets.items()):
                _hash, _index = v
                r = int.to_bytes(int(k), length=2, byteorder="big", signed=False)
                r += bytes.fromhex(_hash)
                r += int.to_bytes(_index, length=8, byteorder="big", signed=False)
                buckets_bytes += r
            payload['revocation_store'] = {
                'index': self.revocation_store['index'],
                'buckets': buckets_bytes,
            }
            a, b = self.convert_config_to_payload(self.remote_config, self.remote_ctn)
            payload['remote_config'] = a
            payload['remote_ctx'] = b
        if owner != REMOTE:
            a, b = self.convert_config_to_payload(self.local_config, self.local_ctn)
            payload['local_config'] = a
            payload['local_ctx'] = b
            encrypted_seed = self.local_config['encrypted_seed']
            payload['encrypted_seed'] = {'seed': bytes.fromhex(encrypted_seed)}

        payload_fd = io.BytesIO()
        PeerBackupWireSerializer.write_tlv_stream(
            fd=payload_fd,
            tlv_stream_name="payload",
            **payload)
        payload_bytes = payload_fd.getvalue()
        return payload_bytes

    @classmethod
    def merge_peerbackup_bytes(cls, local_peerbackup_bytes, remote_peerbackup_bytes):
        local_peerbackup = PeerBackup.from_bytes(local_peerbackup_bytes)
        remote_peerbackup = PeerBackup.from_bytes(remote_peerbackup_bytes)
        #
        local_peerbackup.revocation_store = remote_peerbackup.revocation_store
        #
        local_peerbackup.remote_config = remote_peerbackup.remote_config
        remote_peerbackup.local_config = local_peerbackup.local_config
        #
        remote_peerbackup.local_ctn = local_peerbackup.local_ctn
        local_peerbackup.remote_ctn = remote_peerbackup.remote_ctn
        # merge htlc logs
        local_htlc_log = local_peerbackup.htlc_log
        remote_htlc_log = remote_peerbackup.htlc_log
        print(local_htlc_log)
        print(remote_htlc_log)
        print('------------')
        for proposer in [LOCAL, REMOTE]:
            for htlc_id, local_v in list(local_htlc_log[proposer].items()):
                remote_v = remote_htlc_log[proposer].get(htlc_id)
                if remote_v:
                    local_v.update_remote(remote_v)
                    local_htlc_log[proposer][htlc_id] = local_v
        for proposer in [LOCAL, REMOTE]:
            for htlc_id, remote_v in list(remote_htlc_log[proposer].items()):
                local_v = local_htlc_log[proposer].get(htlc_id)
                if local_v:
                    remote_v.update_local(local_v)
                    remote_htlc_log[proposer][htlc_id] = remote_v
        assert local_htlc_log == remote_htlc_log

        # merge fee_update logs
        local_fee_updates_log = local_peerbackup.fee_updates_log
        remote_fee_updates_log = remote_peerbackup.fee_updates_log
        for proposer in [LOCAL, REMOTE]:
            for fee_update_id, local_v in list(local_fee_updates_log[proposer].items()):
                remote_v = remote_fee_updates_log[proposer].get(fee_update_id)
                if remote_v:
                    local_v.ctn_remote = remote_v.ctn_remote
                    local_fee_updates_log[proposer][fee_update_id] = local_v
        for proposer in [LOCAL, REMOTE]:
            for fee_update_id, remote_v in list(remote_fee_updates_log[proposer].items()):
                local_v = local_fee_updates_log[proposer].get(fee_update_id)
                if local_v:
                    remote_v.ctn_local = local_v.ctn_local
                    remote_fee_updates_log[proposer][fee_update_id] = remote_v
        assert local_fee_updates_log == remote_fee_updates_log

        if local_peerbackup != remote_peerbackup:
            if cls.DEBUG_PEERBACKUP:
                with open('before_local_peerbackup', 'w+', encoding='utf-8') as f:
                    json.dump(json.loads(local_peerbackup_bytes), f, indent=4, sort_keys=True)
                with open('before_remote_peerbackup', 'w+', encoding='utf-8') as f:
                    json.dump(json.loads(remote_peerbackup_bytes), f, indent=4, sort_keys=True)
                with open('merged_peerbackup_local', 'w+', encoding='utf-8') as f:
                    json.dump(local_peerbackup, f, indent=4, sort_keys=True)
                with open('merged_peerbackup_remote', 'w+', encoding='utf-8') as f:
                    json.dump(remote_peerbackup, f, indent=4, sort_keys=True)
            raise Exception('merge_peerbackup error')

        return local_peerbackup.to_bytes()

    def flip_values(self):
        def flip_values(d:dict, key_a, key_b):
            a = d.pop(key_a)
            b = d.pop(key_b)
            d[key_a] = b
            d[key_b] = a

        x = self.remote_ctn
        self.remote_ctn = self.local_ctn
        self.local_ctn = x

        x = self.remote_config
        self.remote_config = self.local_config
        self.local_config = x

        flip_values(self.htlc_log, LOCAL, REMOTE)
        for proposer in [LOCAL, REMOTE]:
            for htlc_id, v in self.htlc_log[proposer].items():
                v.flip()

        flip_values(self.fee_updates_log, LOCAL, REMOTE)
        for proposer in [LOCAL, REMOTE]:
            for fee_update_id, v in self.fee_updates_log[proposer].items():
                v.flip()

        self.constraints['is_initiator'] = not self.constraints['is_initiator']

    def recreate_channel_state(self, lnworker) -> dict:
        """ returns a json compatible with channel storage """
        local_config = self.local_config
        encrypted_seed = bytes.fromhex(local_config.pop('encrypted_seed'))
        channel_seed = lnworker.decrypt_channel_seed(encrypted_seed)
        local_config['channel_seed'] = channel_seed.hex()
        local_config['funding_locked_received'] = True
        node = BIP32Node.from_rootseed(channel_seed, xtype='standard')
        keypair_generator = lambda family: generate_keypair(node, family)
        local_config['per_commitment_secret_seed'] = keypair_generator(LnKeyFamily.REVOCATION_ROOT).privkey.hex()
        local_config['multisig_key']['privkey'] = keypair_generator(LnKeyFamily.MULTISIG).privkey.hex()
        local_config['htlc_basepoint']['privkey'] = keypair_generator(LnKeyFamily.HTLC_BASE).privkey.hex()
        local_config['delayed_basepoint']['privkey'] = keypair_generator(LnKeyFamily.DELAY_BASE).privkey.hex()
        local_config['revocation_basepoint']['privkey'] = keypair_generator(LnKeyFamily.REVOCATION_BASE).privkey.hex()
        state = self.to_json()
        state['onion_keys'] = {}
        state['unfulfilled_htlcs'] = {}
        state['peer_network_addresses'] = {}
        # rebuild the log from local and remote
        log = {
            '1': deepcopy(LOG_TEMPLATE),
            '-1': deepcopy(LOG_TEMPLATE)
        }
        htlc_log = state.pop('htlc_log')
        fee_updates_log = state.pop('fee_updates_log')
        for proposer in [LOCAL, REMOTE]:
            target_log = log[str(int(proposer))]
            for htlc_id, v in htlc_log[proposer].items():
                target_log['adds'][htlc_id] = (v.amount_msat, v.payment_hash, v.cltv_abs, v.htlc_id, v.timestamp)
                assert (v.local_ctn_in is not None or v.remote_ctn_in is not None), v
                target_log['locked_in'][htlc_id] = {'1':v.local_ctn_in, '-1':v.remote_ctn_in}
                if v.local_ctn_out is not None or v.remote_ctn_out is not None:
                    target_log['settles' if v.is_success else 'fails'][htlc_id] = {'1':v.local_ctn_out, '-1':v.remote_ctn_out}

            for fee_update_id, v in fee_updates_log[proposer].items():
                target_log['fee_updates'][fee_update_id] = {'rate':v.rate, 'ctn_local':v.ctn_local, 'ctn_remote':v.ctn_remote}

        log['1']['ctn'] = state.pop('local_ctn')
        log['-1']['ctn'] = state.pop('remote_ctn')
        lnworker.logger.info(f'{log}')
        state['log'] = log
        state['log']['1']['was_revoke_last'] = False
        state['log']['1']['unacked_updates'] = {}
        # restore next_htlc_id
        log = state['log']
        for owner in ['-1', '1']:
            htlc_ids = [int(x) for x in log[owner]['locked_in'].keys()]
            log[owner]['next_htlc_id'] = max(htlc_ids) + 1 if htlc_ids else 0
        # set revack_pending
        log['1']['revack_pending'] = False
        log['-1']['revack_pending'] = True
        # assume OPEN
        state['state'] = 'OPEN'
        state['short_channel_id'] = None
        state['data_loss_protect_remote_pcp'] = {}
        return state
