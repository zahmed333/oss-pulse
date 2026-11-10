# oss-pulse demo: code that runs during `npm install`

Not a real package. `package.json` has a `postinstall` script that decodes a string and runs it, which is how the Shai-Hulud worm and the Nx compromise ran on developers' machines. Here the hidden string is only `console.log('oss-pulse demo')`.

```sh
oss-pulse scan examples/npm-install-hook
```
