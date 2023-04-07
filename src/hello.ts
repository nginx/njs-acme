export function hello(r: NginxHTTPRequest): void {
    const name = 'world'

    return r.return(200, `
      Hello, ${name}!
    `)
}
