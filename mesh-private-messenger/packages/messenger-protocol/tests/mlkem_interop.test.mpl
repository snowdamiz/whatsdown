# ML-KEM-768 against an independent implementation.
#
# The runtime's ML-KEM comes from one Rust crate that has had no outside audit.
# These values were made by OpenSSL 3.6.3, which shares no code with it:
#
#   openssl genpkey -algorithm ML-KEM-768 -pkeyopt hexseed:000102...3f
#   node: crypto.encapsulate(public key) -> ciphertext and shared secret
#   node: ChaCha20-Poly1305, that secret as key, a zero nonce, the data below
#
# The same seed has to give the same public key, which pins key generation
# (FIPS 203 KeyGen_internal, seed laid out as d then z) and the encoding. The
# ciphertext has to decapsulate to the same shared secret. A secret cannot be
# read out here, so it is compared by what it does: it seals the same message
# to the same bytes.

fn openssl_public_key() -> String do
  "298aa10d423c8dda069d02bc59e6cdf03a096b8b3da4cab9b80ca4a14907672c" <> "cef1ec4faf234a0bc5b7e9d473f2b3133b3b26a1d175cb67a7805919699c02f7" <> "6531b99c5f89180704bb4ca4535c5b8972679c660a07c5e514b87009c862eb8f" <> "5157695efb3fc40a9def6b81c1cc02a249ae4f094ad0d9bd3485c1c1c6808052" <> "0a7c8c632032cee738154e5c5176c07da56024776a430fe76eacf665a3f7b832" <> "102215bc82f10939c8355704336a8fac1d81e4bb0485aa5d7c74d6b59bbe5c5e" <> "972a0d8bac411b55b5d5557cd680a1a8f71b4eb86bc48c9a0509731a54bd9d72" <> "90b27963e4372dc9b199cfdcac0b01acd28a62395112e4c43648d622c48c8234" <> "d01440e8cc376c927f23a5afc9ac0474c662274e424525c8552ece3b3fe26516" <> "de901bc7d515bde89558e626c95c80b93342f8010004f39e6c6c94871c5e344c" <> "ab3966c835f9a96a59afd31c40286b38b1c1a78470bab947518934453ce86736" <> "a919f1f5a6d510a86f5454fc3980cb5c765bd2bd5f7b36b1410d6635c8ceb47c" <> "4dda0d76a28eac939c71c3024804866c71626658442163c2c22117e50acefce6" <> "378a985652302a4ef0c2ce0cc716b7796e2b6b2e3777dfa1ac3da259a31b5a9b" <> "530f8cb638a81a62ac301849abaf95a7301bda30068909bfdb7e67dbccbb38a5" <> "551a25b1a3a0f685748ad5753d8880f0016c627486166384c5571fe236590036" <> "4d038311e2d875db366686932b5ec602430a369e87a6ef5c338786657825bd4c" <> "057aceb923eb0935e6905e63b4ced7f80857a773dd64b150d26612ea9ac12052" <> "db2017bf1843ccb4b3281b690dc728adfa85c00281b8e3c09287335f856b4fc2" <> "892f69a2f57921ada01914c40988662d57769662a786351b9b66493dab79594d" <> "986de2100d65ba0ff4ea58b81538d24a4435a258fac25404aa7f41f658b13850" <> "65e158dcb60115732720f40459aaac15e406953a90ac52997d1ccd070060efc6" <> "5db9e653354467fad56ec713c86e7540c423acf2669f52fa6f4ac6888d871ef3" <> "e847c029a8aafbb92e17b24aa079b1f419ba6175b442afb11909d4a56b70a033" <> "5b28739218aa7c9348e2c3c2f3eb3d15a41e6417c0dd94bfeb21419b311a7bb1" <> "3a180bbe833218a9a6b17447cc85f225859587a73077049acbcfd44d0f025438" <> "e15d1538270d586e1bf83192a9459cf63c0e972f85297679831ecf121509851c" <> "b8340f6f107b0fa1a0efd1b36a8189bc085c4f5cb784e553f41b918f80397ce1" <> "956f785bee377ca9aa8be6998ada30c26b7c3d8c6b55254cc96203b20c42aee0" <> "ac4e1ebb408e49a9e3f879d0ab0785eb7025425d1305a2299c015e120d163b0e" <> "19494ce57253d0246d182745cb8197ab7438b3c1bb7972bec5a306eba3567855" <> "c014699fef65ae54c770a0d85c18400cf642aedc660777ba4b138502bd5a7812" <> "f621f84a48296b98dd4322b6f15828b8a8f0e00a8ba44a53c3a8b143571b0740" <> "abd567daf1cde9c79c204b6d5e259d1766a31bbbcb4e6a05cf4502176b301c1c" <> "2f41247750157bcec85e809b30a4d60d7747cdd0f5b99aa8c826987517793aaa" <> "8080a0b124a8558df72bbe37b75f4edbb6be8216d6c633fb2b2280e25113d869" <> "5e43481c3eeb397eb192505229b67a201ea893c3e2cb32da8bc342fa4dea0578"
end

fn openssl_ciphertext() -> String do
  "5d970c5ab98d1566a3fab0b29838261cc5a183889157e3f87bfcf4a50fd7762b" <> "fffaddfb69b74d579d76fd887bbfc92fc0a2eebd7679d2cd7b7b4ec0a9c29eb0" <> "fbf53d42063284a8e1d90775fd74a0fb6ea0c8062cb8f8e5bf493aeb386281c0" <> "0c73d88afc5d297eed8f43791a9d52f04b75f3e9cca07a3b1215a766399bc87a" <> "d8bf11de0c11a74358f535228e4e34aaf6b786245ac2aebd07185ac7acea83b9" <> "33ae49dc9ad9b0f43de8dc19b55d76b846a26611f49d40b4a049bb0e1c43bb73" <> "f9610446333e68d00212980041aaf6f522da465076c5d95f583ae05d9c568e1d" <> "b9a131f57108852df0d03929a02956a897b6ce553b52d8f490109b423298b456" <> "47750a7e60096d87fe8f25e982c197db4cea3e8bc46e6be7b1700da740722d01" <> "3e2423eedeb584c9f6c26e8b316703a266aae3d1fc98cffe5abd9fcce846db82" <> "0c1c182c2ce0dd28526d467538990e0c6565017994aebb395d252ca27e42ed6e" <> "12ef2874b1bfcfef14dbc46a312788e423b3b7d9f5f8381d59ed959e4a602857" <> "89127abf2dfa7de5fb7755b5ebde5e7b0e785338f0186211b18e92d66b0ab600" <> "859cc9ee5b12b160f1bf3d3bdfe954ee0af4cacd62270024859fcaa8d35fd910" <> "8c3f4e6bbe33fc091d55734de7d6b249f7c230ce74465ed1685f378051f3169c" <> "a085373ec5862ab9abc224c47b0dfa195f1d2849408002d706fab37dfddb9492" <> "b336000f66612e867edb39f2e03956cbc7a63c9e8b1888278f4ea235c8b7d818" <> "9f9d31a43a951061d8531c4e2b4b451c090889ea9b47ee24a5dca40d8068aba6" <> "3b26407b81a910cb4720c1330d3d19d9b1a272275f62a0003225c84928781d48" <> "1f610bf27e70afc25a5e1fcf1b003461f6f709cabf24bd898d64e649fd8f0bc0" <> "3a666881258a2f5af0777f3d49564d372cf575fbf32e98816238bf23e8c57194" <> "584d3d7f3711d41c864f40338f30f3577b02cb73f85ef05cd67d56c6b7e24881" <> "0d8a1abde5bbdd5ecdc8393f2384a5382f58bbb740328843f11d31183fb2f4ac" <> "c7debbc754c3b67694d3fc4d3f6af740d35cb16e48e4e263725d4b11d5387657" <> "e3b4456c60650bae504ad4c5d4c2d54390c4705eab6b8127e5790139c875001d" <> "2162a34dc7dc3fdd1d85396d9771bde4fff3245378499a81ed62d1f0b75e91ec" <> "c11928ef408313f1c45a405f12d57aa0c5a68bb69a2b7be58bd5b725e30f4299" <> "2a49f155a2ef72dba186fd4879cca93a82b4a17a2f5e650c596351bb166c68dc" <> "1f55baf1115e808fbff0c581cbee62730cd7122de13aecae3b52e226d1855dc6" <> "8bb2428f7bece42dd6c5295745857769a9902d15b743dd9eec39f36dedf4f6be" <> "1909bc71623d7bd0ff5d058978cb6984e125e5e8cc2d642f303bed10ff9dacbc" <> "3867a4145b71b6d1fc44ff8d6b0c9ae31848e0b198f18068a71c9a87c2058032" <> "19a863d4ae881effb84079b5fd85d3a7dab14b4ff3f2f0f8b382ef662ad5b8c5" <> "717dd6bd9e3cf8c5813e94801b3361253e927103864dac7373bd56c80cac8533"
end

fn seed() -> Bytes ! String do
  Bytes.from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
end

fn sealed_under(secret :: SecretBytes) -> Bytes ! String do
  let key = case Crypto.aead_key(secret) do
    Err(_) -> Err("aead key failed")
    Ok(value) -> Ok(value)
  end ?
  case Crypto.aead_seal(key,
  Bytes.from_hex("000000000000000000000000") ?,
  Bytes.from_utf8("mesh-msg/test/ml-kem-768-interop"),
  Bytes.from_utf8("ml-kem-768 interop")) do
    Err(_) -> Err("seal failed")
    Ok(value) -> Ok(value)
  end
end

fn proof() -> Bool ! String do
  let pair = case Crypto.mlkem_from_seed(seed() ?) do
    Err(_) -> Err("key generation failed")
    Ok(value) -> Ok(value)
  end ?
  let public_key = pair.public_key
  let private_key = pair.private_key
  assert(Bytes.to_hex(public_key.bytes) == openssl_public_key())
  let shared = case Crypto.mlkem_decapsulate(private_key,
  MlKemCiphertext { bytes : Bytes.from_hex(openssl_ciphertext()) ? }) do
    Err(_) -> Err("decapsulation failed")
    Ok(value) -> Ok(value)
  end ?
  assert(Bytes.to_hex(sealed_under(shared) ?) == "bed5d518c5ba3e0709514470332dbb13d0954d757b5918e7d94f452757b99d85c3a9")
  # A ciphertext that was tampered with still decapsulates, to an unrelated
  # secret: ML-KEM rejects implicitly, so nothing tells an attacker it failed.
  let pair_again = case Crypto.mlkem_from_seed(seed() ?) do
    Err(_) -> Err("key generation failed")
    Ok(value) -> Ok(value)
  end ?
  let tampered = Bytes.from_hex("ff" <> String.slice(openssl_ciphertext(), 2, 2176)) ?
  let other = case Crypto.mlkem_decapsulate(pair_again.private_key,
  MlKemCiphertext { bytes : tampered }) do
    Err(_) -> Err("tampered decapsulation failed")
    Ok(value) -> Ok(value)
  end ?
  assert(Bytes.to_hex(sealed_under(other) ?) != "bed5d518c5ba3e0709514470332dbb13d0954d757b5918e7d94f452757b99d85c3a9")
  Ok(true)
end

test("ML-KEM-768 agrees with OpenSSL on key generation from a seed and on decapsulation") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
