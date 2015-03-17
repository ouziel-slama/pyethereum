from pyethereum import blocks, utils, db
import rlp

import pytest, os, sys
import pyethereum.testutils as testutils

from pyethereum.slogging import get_logger, configure_logging
logger = get_logger()


def translate_keys(olddict, keymap, valueconv, deletes):
    o = {}
    for k in olddict.keys():
        if k not in deletes:
            o[keymap.get(k, k)] = valueconv(k, olddict[k])
    return o


e = db.EphemDB()

translator_list = {
    "extra_data": "extraData",
    "gas_limit": "gasLimit",
    "gas_used": "gasUsed",
    "mixhash": "mixHash",
    "prevhash": "parentHash",
    "receipts_root": "receiptTrie",
    "seedhash": "seedHash",
    "tx_list_root": "transactionsTrie",
    "uncles_hash": "uncleHash",
    "gas_price": "gasPrice",
    "header": "blockHeader",
    "uncles": "uncleHeaders"
}


def valueconv(k, v):
    if k in ['r', 's']:
        return '0x'+utils.int_to_big_endian(v).encode('hex')
    return v


def run_block_test(params):
    b = blocks.genesis(e, params["pre"])
    gbh = params["genesisBlockHeader"]
    b.seedhash = utils.scanners['bin'](gbh["seedHash"])
    b.bloom = utils.scanners['int256b'](gbh["bloom"])
    b.timestamp = utils.scanners['int'](gbh["timestamp"])
    b.nonce = utils.scanners['bin'](gbh["nonce"])
    b.extra_data = utils.scanners['bin'](gbh["extraData"])
    b.gas_limit = utils.scanners['int'](gbh["gasLimit"])
    b.gas_used = utils.scanners['int'](gbh["gasUsed"])
    b.coinbase = utils.scanners['addr'](gbh["coinbase"])
    b.difficulty = int(gbh["difficulty"])
    b.prevhash = utils.scanners['bin'](gbh["parentHash"])
    b.mixhash = utils.scanners['bin'](gbh["mixHash"])
    assert b.receipts.root_hash == \
        utils.scanners['bin'](gbh["receiptTrie"])
    assert b.transactions.root_hash == \
        utils.scanners['bin'](gbh["transactionsTrie"])
    assert utils.sha3rlp(b.uncles) == \
        utils.scanners['bin'](gbh["uncleHash"])
    h = b.state.root_hash.encode('hex')
    if h != gbh["stateRoot"]:
        raise Exception("state root mismatch")
    if b.hash != utils.scanners['bin'](gbh["hash"]):
        raise Exception("header hash mismatch")
    assert blocks.check_header_pow(b.serialize_header(), e)
    for blk in params["blocks"]:
        rlpdata = blk["rlp"][2:].decode('hex')
        if 'blockHeader' not in blk:
            try:
                b = b.deserialize_child(rlpdata)
                success = True
            except:
                success = False
            assert not success
        else:
            b = b.deserialize_child(rlpdata)
        # blkdict = b.to_dict(False, True, False, True)
        # assert blk["blockHeader"] == \
        #     translate_keys(blkdict["header"], translator_list, lambda y, x: x, [])
        # assert blk["transactions"] == \
        #     [translate_keys(t, translator_list, valueconv, ['hash'])
        #      for t in blkdict["transactions"]]
        # assert blk["uncleHeader"] == \
        #     [translate_keys(u, translator_list, lambda x: x, [])
        #      for u in blkdict["uncles"]]


def do_test_block(filename, testname=None, testdata=None, limit=99999999):
    logger.debug('running test:%r in %r' % (testname, filename))
    run_block_test(testdata)

if __name__ == '__main__':
    assert len(sys.argv) >= 2, "Please specify file or dir name"
    fixtures = testutils.get_tests_from_file_or_dir(sys.argv[1])
    if len(sys.argv) >= 3:
        for filename, tests in fixtures.items():
            for testname, testdata in tests.items():
                if testname == sys.argv[2]:
                    print("Testing: %s %s" % (filename, testname))
                    run_block_test(testdata)
    else:
        for filename, tests in fixtures.items():
            for testname, testdata in tests.items():
                print("Testing: %s %s" % (filename, testname))
                run_block_test(testdata)
else:
    fixtures = testutils.get_tests_from_file_or_dir(
        os.path.join('fixtures', 'BlockTests'))
    for filename, tests in fixtures.items():
        for testname, testdata in tests.items()[:500]:
            func_name = 'test_%s_%s' % (filename, testname)
            globals()[func_name] = lambda: do_test_block(filename, testname, testdata)
