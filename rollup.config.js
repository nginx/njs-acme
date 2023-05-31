// @ts-check
import addGitMsg from 'rollup-plugin-add-git-msg'
import babel from '@rollup/plugin-babel'
import commonjs from '@rollup/plugin-commonjs'
import resolve from '@rollup/plugin-node-resolve'
import json from "@rollup/plugin-json";
import pkg from './package.json'


// List of njs built-in modules.
const njsExternals = ['crypto', 'fs', 'querystring']
const isEnvProd = process.env.NODE_ENV === 'production'

/**
 * Plugin to fix syntax of the default export to be compatible with njs.
 * (https://github.com/rollup/rollup/pull/4182#issuecomment-1002241017)
 *
 * @return {import('rollup').OutputPlugin}
 */
const fixExportDefault = () => ({
    name: 'fix-export-default',
    renderChunk: (code) => ({
        code: code.replace(/\bexport { (\S+) as default };/, 'export default $1;'),
        map: null,
    }),
})

/**
 * @type {import('rollup').RollupOptions}
 */
const options = {
    input: 'src/index.ts',
    external: njsExternals,
    plugins: [
        // Transpile TypeScript sources to JS.
        babel({
            babelHelpers: 'bundled',
            envName: 'njs',
            extensions: ['.ts', '.mjs', '.js'],
        }),
        // Resolve node modules.
        resolve({
            extensions: ['.mjs', '.js', '.json', '.ts'],
        }),
        json(),
        // Convert CommonJS modules to ES6 modules.
        commonjs(),
        // Fix syntax of the default export.
        fixExportDefault(),
        // Plugins to use in production mode only.
        ...isEnvProd ? [
            // Add git tag, commit SHA, build date and copyright at top of the file.
            addGitMsg(),
        ] : [],
    ],
    output: {
        file: pkg.main,
        format: 'es',
    },
}
export default options
