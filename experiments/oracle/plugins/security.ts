import { type BunPlugin } from "bun";

const security: BunPlugin = {
  name: "security-plugin",
  setup(build) {
    build.onResolve({ filter: /.*secure\// }, ({ importer }) => {
      console.log(importer);
      if (importer.includes("/browser/")) {
        throw new Error(
          `Client context attempting to resolve restricted import`
        );
      }
      return null;
    });
  },
};

export default security;
