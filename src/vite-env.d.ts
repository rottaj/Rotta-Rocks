/// <reference types="vite/client" />

const { resolve } = require("path");
const { defineConfig } = require("vite");

declare var require: any
declare module 'three';
declare module 'definConfig';


module.exports = defineConfig({
  build: {
    rollupOptions: {
        input: {
            main: resolve(__dirname, "index.html"),
        }
    }
  }
})