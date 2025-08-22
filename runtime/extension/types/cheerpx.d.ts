// CheerpX type declarations for remote module
declare const CheerpX: any;

// Allow importing CheerpX from CDN
declare module "https://cxrtnc.leaningtech.com/1.1.5/cx.js" {
  const CheerpX: any;
  export default CheerpX;
}