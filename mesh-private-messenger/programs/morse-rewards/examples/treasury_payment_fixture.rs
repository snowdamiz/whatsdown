//! Test-only persistent SPL/ATA SBF bank. Fixed public keys, no external RPC.
use base64::{engine::general_purpose::STANDARD, Engine};
use litesvm::LiteSVM;
use serde_json::{json, Value};
use solana_account::Account;
use solana_address::Address;
use solana_clock::Clock;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction::{versioned::VersionedTransaction, Transaction};
use std::io::{self, BufRead, Write};
const TOKEN: Address = Address::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const ATA: Address = Address::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
fn ata(owner: &Address, mint: &Address) -> Address {
    Address::find_program_address(&[owner.as_ref(), TOKEN.as_ref(), mint.as_ref()], &ATA).0
}
fn token_account(svm: &mut LiteSVM, address: Address, owner: Address, mint: Address, amount: u64) {
    let mut data = vec![0; 165];
    data[..32].copy_from_slice(mint.as_ref());
    data[32..64].copy_from_slice(owner.as_ref());
    data[64..72].copy_from_slice(&amount.to_le_bytes());
    data[108] = 1;
    svm.set_account(
        address,
        Account {
            lamports: svm.minimum_balance_for_rent_exemption(165),
            data,
            owner: TOKEN,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}
struct Bank {
    svm: LiteSVM,
    payer: Keypair,
    authority: Keypair,
    nonce: Keypair,
    source: Keypair,
    buyer: Keypair,
    mint: Address,
    destination: Address,
}
impl Bank {
    fn new() -> Self {
        let mut svm = LiteSVM::new();
        let payer = Keypair::new_from_array([1; 32]);
        let authority = Keypair::new_from_array([2; 32]);
        let nonce = Keypair::new_from_array([3; 32]);
        let source = Keypair::new_from_array([4; 32]);
        let buyer = Keypair::new_from_array([5; 32]);
        let mint = Address::new_from_array([0x44; 32]);
        let destination = Address::new_from_array([9; 32]);
        let mut clock = svm.get_sysvar::<Clock>();
        clock.slot = 100000;
        clock.unix_timestamp = 1700000010;
        svm.set_sysvar(&clock);
        svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();
        svm.airdrop(&buyer.pubkey(), 1_000_000_000).unwrap();
        let units: u64 = std::env::var("TREASURY_SBF_BUYER_UNITS")
            .unwrap_or("4999999".into())
            .parse()
            .unwrap();
        let mut data = vec![0; 82];
        data[36..44].copy_from_slice(&(100_000_000_000u64 + units).to_le_bytes());
        data[44] = 6;
        data[45] = 1;
        svm.set_account(
            mint,
            Account {
                lamports: svm.minimum_balance_for_rent_exemption(82),
                data,
                owner: TOKEN,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
        token_account(
            &mut svm,
            ata(&source.pubkey(), &mint),
            source.pubkey(),
            mint,
            100_000_000_000,
        );
        // Independent second deposit for actual immutable packet batching proofs.
        let second_source = Keypair::new_from_array([6; 32]);
        token_account(
            &mut svm,
            ata(&second_source.pubkey(), &mint),
            second_source.pubkey(),
            mint,
            0,
        );
        token_account(
            &mut svm,
            ata(&buyer.pubkey(), &mint),
            buyer.pubkey(),
            mint,
            units,
        );
        let rent = svm.minimum_balance_for_rent_exemption(80);
        let mut create = 0u32.to_le_bytes().to_vec();
        create.extend_from_slice(&rent.to_le_bytes());
        create.extend_from_slice(&80u64.to_le_bytes());
        create.extend_from_slice(&[0; 32]);
        let mut initialize = 6u32.to_le_bytes().to_vec();
        initialize.extend_from_slice(authority.pubkey().as_ref());
        let instructions = [
            Instruction {
                program_id: Address::default(),
                accounts: vec![
                    AccountMeta::new(payer.pubkey(), true),
                    AccountMeta::new(nonce.pubkey(), true),
                ],
                data: create,
            },
            Instruction {
                program_id: Address::default(),
                accounts: vec![
                    AccountMeta::new(nonce.pubkey(), false),
                    AccountMeta::new_readonly(
                        Address::from_str_const("SysvarRecentB1ockHashes11111111111111111111"),
                        false,
                    ),
                    AccountMeta::new_readonly(
                        Address::from_str_const("SysvarRent111111111111111111111111111111111"),
                        false,
                    ),
                ],
                data: initialize,
            },
        ];
        let tx = Transaction::new_signed_with_payer(
            &instructions,
            Some(&payer.pubkey()),
            &[&payer, &nonce],
            svm.latest_blockhash(),
        );
        svm.send_transaction(tx).unwrap();
        Self {
            svm,
            payer,
            authority,
            nonce,
            source,
            buyer,
            mint,
            destination,
        }
    }
    fn amount(&self, address: Address) -> u64 {
        self.svm
            .get_account(&address)
            .filter(|a| a.owner == TOKEN && a.data.len() == 165)
            .map_or(0, |a| {
                u64::from_le_bytes(a.data[64..72].try_into().unwrap())
            })
    }
    fn state(&self) -> Value {
        let account = self.svm.get_account(&self.nonce.pubkey()).unwrap();
        assert_eq!(account.data.len(), 80);
        json!({"rail":"usdc","payer":self.payer.pubkey().to_string(),"authority":self.authority.pubkey().to_string(),"source":self.source.pubkey().to_string(),"destination":self.destination.to_string(),"buyer":self.buyer.pubkey().to_string(),"address":self.nonce.pubkey().to_string(),"nonce":Address::new_from_array(account.data[40..72].try_into().unwrap()).to_string(),"lamports_per_signature":u64::from_le_bytes(account.data[72..80].try_into().unwrap()).to_string(),"cluster":Address::new_from_array([0x11;32]).to_string(),"recent_blockhash":self.svm.latest_blockhash().to_string(),"timestamp":self.svm.get_sysvar::<Clock>().unix_timestamp.to_string(),"account":{"owner":account.owner.to_string(),"data_base64":STANDARD.encode(account.data),"lamports":account.lamports.to_string(),"executable":false},"source_token_balance":self.amount(ata(&self.source.pubkey(),&self.mint)).to_string(),"buyer_token_balance":self.amount(ata(&self.buyer.pubkey(),&self.mint)).to_string(),"destination_token_balance":self.amount(ata(&self.destination,&self.mint)).to_string()})
    }
    fn tokens(&self, keys: &[Address]) -> Vec<Value> {
        keys.iter().enumerate().filter_map(|(index,key)|{let account=self.svm.get_account(key)?;if account.owner!=TOKEN||account.data.len()!=165{return None}Some(json!({"accountIndex":index,"mint":self.mint.to_string(),"owner":Address::new_from_array(account.data[32..64].try_into().unwrap()).to_string(),"programId":TOKEN.to_string(),"uiTokenAmount":{"amount":u64::from_le_bytes(account.data[64..72].try_into().unwrap()).to_string(),"decimals":6,"uiAmount":null,"uiAmountString":"0"}}))}).collect()
    }
    fn send(&mut self, wire: Vec<u8>) -> Value {
        let tx: VersionedTransaction = bincode::deserialize(&wire).unwrap();
        let keys = tx.message.static_account_keys().to_vec();
        let before = self.state();
        let pre = keys
            .iter()
            .map(|k| self.svm.get_account(k).map_or(0, |a| a.lamports))
            .collect::<Vec<_>>();
        let pre_tokens = self.tokens(&keys);
        let result = self.svm.send_transaction(tx);
        let (meta, error) = match result {
            Ok(meta) => (meta, None),
            Err(error) => (error.meta, Some(error.err)),
        };
        let post = keys
            .iter()
            .map(|k| self.svm.get_account(k).map_or(0, |a| a.lamports))
            .collect::<Vec<_>>();
        let post_tokens = self.tokens(&keys);
        let inner=meta.inner_instructions.iter().enumerate().filter(|(_,rows)|!rows.is_empty()).map(|(index,rows)|json!({"index":index,"instructions":rows.iter().map(|row|json!({"programIdIndex":row.instruction.program_id_index,"accounts":row.instruction.accounts,"data_hex":hex::encode(&row.instruction.data),"stackHeight":row.stack_height})).collect::<Vec<_>>()})).collect::<Vec<_>>();
        let response=json!({"jsonrpc":"2.0","id":41,"result":{"slot":100000,"blockTime":self.svm.get_sysvar::<Clock>().unix_timestamp,"version":"legacy","transaction":[STANDARD.encode(&wire),"base64"],"meta":{"err":error,"fee":meta.fee,"loadedAddresses":{"writable":[],"readonly":[]},"innerInstructions":inner,"preBalances":pre,"postBalances":post,"preTokenBalances":pre_tokens,"postTokenBalances":post_tokens}}}).to_string();
        json!({"ok":error.is_none(),"error":format!("{error:?}"),"fee":meta.fee.to_string(),"before":before,"after":self.state(),"rpc_response":response,"sbf_logs":meta.logs})
    }
    fn handle(&mut self, request: Value) -> Value {
        match request["method"].as_str().unwrap() {
            "state" => self.state(),
            "expire" => {
                self.svm.expire_blockhash();
                self.state()
            }
            "send" => self.send(hex::decode(request["wire_hex"].as_str().unwrap()).unwrap()),
            "close_buyer_ata" => {
                assert_eq!(self.amount(ata(&self.buyer.pubkey(), &self.mint)), 0);
                let ix = Instruction {
                    program_id: TOKEN,
                    accounts: vec![
                        AccountMeta::new(ata(&self.buyer.pubkey(), &self.mint), false),
                        AccountMeta::new(self.buyer.pubkey(), false),
                        AccountMeta::new_readonly(self.buyer.pubkey(), true),
                    ],
                    data: vec![9],
                };
                let tx = Transaction::new_signed_with_payer(
                    &[ix],
                    Some(&self.buyer.pubkey()),
                    &[&self.buyer],
                    self.svm.latest_blockhash(),
                );
                self.svm.send_transaction(tx).unwrap();
                self.state()
            }
            _ => panic!("unsupported local fixture method"),
        }
    }
}
fn main() {
    let mut bank = Bank::new();
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let value: Value = serde_json::from_str(&line).unwrap();
        println!("{}", bank.handle(value));
        io::stdout().flush().unwrap();
    }
}
