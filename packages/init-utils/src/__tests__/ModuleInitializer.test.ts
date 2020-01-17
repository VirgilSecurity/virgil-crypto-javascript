import { expect } from 'chai';

import { ModuleAlreadyExistsError, ModuleNotFoundError } from '../errors';
import { ModuleInitializer } from '../ModuleInitializer';

describe('ModuleInitializer', () => {
  let moduleInitializer: ModuleInitializer;

  beforeEach(() => {
    moduleInitializer = new ModuleInitializer();
  });

  describe('addModule', () => {
    it("throws 'ModuleAlreadyExistsError' if module already added", () => {
      const moduleName = 'module';
      moduleInitializer.addModule(moduleName, () => Promise.resolve());
      const error = () => moduleInitializer.addModule(moduleName, () => Promise.resolve());
      expect(error).to.throw(ModuleAlreadyExistsError);
    });
  });

  describe('getModule', () => {
    it('returns the module', () => {
      const moduleName = 'module';
      const module = {};
      moduleInitializer.setModule(moduleName, module);
      const result = moduleInitializer.getModule(moduleName);
      expect(result).to.equal(module);
    });

    it("throws 'ModuleNotFoundError' if module not found", () => {
      const error = () => moduleInitializer.getModule('module');
      expect(error).to.throw(ModuleNotFoundError);
    });
  });

  describe('hasModule', () => {
    it('returns true if module was found', () => {
      const moduleName = 'module';
      moduleInitializer.setModule(moduleName, {});
      expect(moduleInitializer.hasModule(moduleName)).to.be.true;
    });

    it('returns false if module was not found', () => {
      moduleInitializer.setModule('module1', {});
      expect(moduleInitializer.hasModule('module2')).to.be.false;
    });
  });

  describe('setModule', () => {
    it('sets the module', () => {
      const moduleName = 'module';
      moduleInitializer.setModule(moduleName, {});
      expect(moduleInitializer.hasModule(moduleName)).to.be.true;
    });
  });

  describe('removeModule', () => {
    it('removes the module', () => {
      const moduleName = 'module';
      moduleInitializer.setModule(moduleName, {});
      moduleInitializer.removeModule(moduleName);
      expect(moduleInitializer.hasModule(moduleName)).to.be.false;
    });
  });

  describe('loadModule', () => {
    it('returns memoized promise', async () => {
      const moduleName = 'module';
      moduleInitializer.addModule(moduleName, () => Promise.resolve());
      const promise1 = moduleInitializer.loadModule(moduleName);
      await moduleInitializer.loadModule(moduleName);
      const promise2 = moduleInitializer.loadModule(moduleName);
      expect(promise1).to.equal(promise2);
    });

    it("throws 'ModuleNotFoundError' if module was removed", async () => {
      const moduleName = 'module';
      moduleInitializer.addModule(moduleName, () => Promise.resolve());
      moduleInitializer.removeModule(moduleName);
      try {
        await moduleInitializer.loadModule(moduleName);
      } catch (error) {
        expect(error).to.be.instanceOf(ModuleNotFoundError);
      }
    });
  });

  describe('loadModules', () => {
    it('loads all modules', async () => {
      const module1Name = 'module1';
      const module1 = {};
      const module2Name = 'module2';
      const module2 = {};
      moduleInitializer.addModule(module1Name, () => Promise.resolve(module1));
      moduleInitializer.addModule(module2Name, () => Promise.resolve(module2));
      await moduleInitializer.loadModules();
      expect(moduleInitializer.getModule(module1Name)).to.equal(module1);
      expect(moduleInitializer.getModule(module2Name)).to.equal(module2);
    });

    it('returns memoized promise', async () => {
      moduleInitializer.addModule('module1', () => Promise.resolve());
      moduleInitializer.addModule('module2', () => Promise.resolve());
      const promise1 = moduleInitializer.loadModules();
      await moduleInitializer.loadModules();
      const promise2 = moduleInitializer.loadModules();
      expect(promise1).to.equal(promise2);
    });

    it('returns new promise if called after new module was added', async () => {
      moduleInitializer.addModule('module1', () => Promise.resolve());
      moduleInitializer.addModule('module2', () => Promise.resolve());
      await moduleInitializer.loadModules();
      const promise1 = moduleInitializer.loadModules();
      moduleInitializer.addModule('module3', () => Promise.resolve());
      const promise2 = moduleInitializer.loadModules();
      expect(promise1).not.to.equal(promise2);
    });
  });

  describe('events', () => {
    it("emits 'load' event", done => {
      const moduleName = 'module1';
      const modulePayload = {};
      moduleInitializer.on('load', (name, module) => {
        expect(name).to.equal(moduleName);
        expect(module).to.equal(modulePayload);
        done();
      });
      moduleInitializer.addModule(moduleName, () => Promise.resolve(modulePayload));
      moduleInitializer.loadModules();
    });

    it("emits 'remove' event", done => {
      const moduleName = 'module1';
      const modulePayload = {};
      moduleInitializer.on('remove', (name, module) => {
        expect(name).to.equal(moduleName);
        expect(module).to.equal(modulePayload);
        done();
      });
      moduleInitializer.addModule(moduleName, () => Promise.resolve(modulePayload));
      moduleInitializer.loadModules().then(() => {
        moduleInitializer.removeModule(moduleName);
      });
    });

    it("emits 'error' event", done => {
      const moduleName = 'module1';
      moduleInitializer.on('error', (error, name) => {
        expect(error).to.be.instanceOf(ModuleAlreadyExistsError);
        expect(name).to.equal(moduleName);
        done();
      });
      moduleInitializer.addModule(moduleName, () => Promise.resolve());
      try {
        moduleInitializer.addModule(moduleName, () => Promise.resolve());
      } catch (error) {
        expect(error).to.be.instanceOf(ModuleAlreadyExistsError);
      }
    });
  });
});
