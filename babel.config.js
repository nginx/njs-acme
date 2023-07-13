'use strict'
// @ts-check

/** @type {babel.ConfigFunction} */
// eslint-disable-next-line no-undef
module.exports = (api) => ({
  presets: [
    // Transpile modern JavaScript into code compatible with njs.
    // This is used only for building the dist bundle with Rollup.
    ...(api.env('njs') ? ['babel-preset-njs'] : []),
    // Parse TypeScript syntax and transform it to JavaScript (i.e. it strips
    // type annotations, but does not perform type checking).
    [
      '@babel/preset-typescript',
      {
        allowDeclareFields: true,
      },
    ],
  ],

  plugins: [
    ...(!api.caller((c) => c && c.supportsStaticESM)
      ? [
          // Transform ES modules to CommonJS if needed  needed for Mocha tests).
          // Mocha, babel-node, babel/register etc. don't understand ES module
          // syntax, so we have to transform it to CommonJS.
          // This is not used with Rollup.
          '@babel/plugin-transform-modules-commonjs',
        ]
      : []),
    ...(api.env('mocha')
      ? [
          // Transform power-assert. This is used only for Mocha tests.
          'babel-plugin-empower-assert',
          'babel-plugin-espower',
        ]
      : []),
  ],
})
