### The protocol

1. A message receiver (let's call them Bob) prepares an elliptic key pair and sends the public key to the message sender (let's call them Alice).

2. Alice finds system participants who are willing to store the message. Let call them Keepers. Keepers will receive a fee from Alice.

3. Each of the Keepers generates an elliptic key pair and provide the public key to Alice.

4. Alice publishes a smart contract, whitelisting the selected Keepers' public keys.

5. Keepers join the contract by freezing some amount of Ether (stake).

6. Alice encrypts the message with the Bob's public key. Then, she generates a new symmetric key and adds the second layer of encryption. After that, she splits symmetric key into a number of parts using Shamir's secret sharing algorithm, one part for each Keeper.

7. Alice encrypts each symmetric key part with a public key of the respective Keeper and finally publishes all encrypted parts into the contract, together with the twice-encrypted message and its original hash.

8. Alice performs regular check-ins, sending a transaction to the contract. Each consecutive check-in should be performed within some predefined period of time. When checking in, Alice sends enough Ether to the contract balance to pay all involved Keepers.

9. Keepers perform regular check-ins, sending a transaction to the contract. When a Keeper checks in, they receive the fee Alice sent to the contract within her last check-in. When a Keeper checks in, they prove that they posess their private key by signing the message formed from the address the TX is being sent from and their last check-in time.

10. Anyone could submit to the contract a private key of a Keeper at any time. The Keeper themselves can do this too. This is done in two steps:

10.1. First, they prove that they posess the private key by signing a message, analogically to 9. This initiates the process of key submission for that particular Keeper. After that, they must wait for N minutes. During that period, another parties can prove that they posess the same key. Let's cxall all such parties Claimers.

10.2. When that period passes, any of the Claimers must provide the private key corresponding to the public key of the Keeper within M minutes.

10.3. If the private key was provided, all Claimers have the right to get their share of the Keeper's stake. The stake is shared equally between all Claimers.

10.4. If the private key wasn't provided or was provided too late, the stake of the Keeper get burnt.

11. When Alice misses a check-in, all Keepers must initiate the procedure described in 10, otherwise their stake get burnt.

12. Bob doesn't know the adress of the contract. To receive the message, he periodically checks all contracts that have private keys of the Keepers supplied, and tries to decrypt the data with his private key.
