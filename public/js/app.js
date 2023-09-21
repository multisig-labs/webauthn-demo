import Alpine from "https://esm.sh/alpinejs@3.13.0";
import { createWallet, clearWallets, getWallets, signTx } from "/js/webauthn.js";
import { post } from "/js/utils.js";

document.addEventListener("alpine:init", () => {
  Alpine.data("wallets", () => ({
    accounts: [],
    wallets: {},
    txs: [],
    signedTx: undefined,
    verificationResponse: undefined,
    async init() {
      await this.refresh();
    },
    async refresh() {
      await this.getWallets();
      await this.getAccounts();
      await this.getTxs();
    },
    async getAccounts() {
      this.accounts = await fetch("/accounts").then((r) => r.json());
    },
    async getWallets() {
      this.wallets = await getWallets();
    },
    async deleteWallets() {
      clearWallets();
      await this.refresh();
    },
    async addFunds(walletName) {
      const address = this.wallets[walletName].address;
      const balance = 100;
      const result = await post("/update_account", { address, balance });
      console.log(result);
      await this.refresh();
    },
    async createWallet(name, mobile = false) {
      name = name || "My Wallet";
      const wallet = await createWallet("Morpheus", name, mobile);
      if (wallet.error) {
        alert(wallet.error);
      } else {
        await this.refresh();
        // Give it some funds on backend
        await post("/account", { address: wallet.address, balance: 100 });
      }
    },
    async signTx(walletName, to, amt) {
      this.tx = { payer: this.wallets[walletName].address, payee: to, amount: parseInt(amt) };
      this.signedTx = await signTx(walletName, this.tx);

      // Send to backend for verification/execution
      const result = await post("/tx", this.signedTx);
      this.verificationResponse = result;
      await this.refresh();
    },
    async getTxs() {
      const txs = await fetch("/txs").then((r) => r.json());
      this.txs = txs.slice(0, 5);
    },
  }));
});

Alpine.start();
