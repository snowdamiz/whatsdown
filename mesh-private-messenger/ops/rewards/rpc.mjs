import { assertIsAddress, createJsonRpcApi, createRpc } from '@solana/kit';
import { parseJsonWithBigInts, stringifyJsonWithBigInts } from '@solana/rpc-spec-types';
import { connectChainWriterRpc } from '../chain-writer/rpc.mjs';
import { rewardsMessage, rewardsSignedStep } from './transactions.mjs';

export function connectRewardsRpc(config,fetcher=globalThis.fetch){
  return connectChainWriterRpc(config,{message:rewardsMessage,signedStep:rewardsSignedStep},
    {assertIsAddress,createJsonRpcApi,createRpc,parseJsonWithBigInts,stringifyJsonWithBigInts},fetcher);
}
