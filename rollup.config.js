// @ts-check
import addGitMsg from 'rollup-plugin-add-git-msg'
import typescript from '@rollup/plugin-typescript';
import commonjs from '@rollup/plugin-commonjs'
import resolve from '@rollup/plugin-node-resolve'

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
        typescript(),
        // Resolve node modules.
        resolve({
            extensions: ['.mjs', '.js', '.json', '.ts'],
        }),
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
    //   output: {
    //     file: pkg.main,
    //     format: 'es',
    //   },
    output: {
        dir: 'dist',
    },
}
export default options
