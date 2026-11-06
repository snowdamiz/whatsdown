import { assertIsAddress, createJsonRpcApi, createRpc } from '@solana/kit';
import { parseJsonWithBigInts, stringifyJsonWithBigInts } from '@solana/rpc-spec-types';
import { relayStepMessage, relaySignedStep } from './transactions.mjs';
import { connectChainWriterRpc } from '../chain-writer/rpc.mjs';

export function connectRelayRpc(config,fetcher=globalThis.fetch){
  return connectChainWriterRpc(config,{message:relayStepMessage,signedStep:relaySignedStep},
    {assertIsAddress,createJsonRpcApi,createRpc,parseJsonWithBigInts,stringifyJsonWithBigInts},fetcher);
}
