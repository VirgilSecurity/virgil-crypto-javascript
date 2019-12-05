import { expect } from 'chai';

import { ModuleInitializerError } from '../errors';
import { ModuleInitializer } from '../ModuleInitializer';

describe('ModuleInitializer', () => {
  describe('module', () => {
    it('returns initialized module', async () => {
      const module = {};
      const initializer = new ModuleInitializer<typeof module>(() => Promise.resolve(module));
      await initializer.initialize();
      expect(initializer.module).to.equal(module);
    });

    it('allows us to set the module', () => {
      const module = {};
      const initializer = new ModuleInitializer<typeof module>(() => Promise.resolve(module));
      initializer.module = module;
      expect(initializer.module).to.equal(module);
    });

    it('throws `ModuleInitializerError` if module is not initialized', () => {
      const module = {};
      const initializer = new ModuleInitializer<typeof module>(() => Promise.resolve(module));
      const error = () => initializer.module;
      expect(error).to.throw(ModuleInitializerError);
    });
  });

  describe('isInitialized', () => {
    it('returns true if module is initialized', async () => {
      const module = {};
      const initializer = new ModuleInitializer<typeof module>(() => Promise.resolve(module));
      expect(initializer.isInitialized).to.be.false;
    });

    it('returns false if module is not initialized', () => {
      const module = {};
      const initializer = new ModuleInitializer<typeof module>(() => Promise.resolve(module));
      expect(initializer.isInitialized).to.be.false;
    });
  });

  describe('initialize', () => {
    it('initializes module successfully', async () => {
      const module = {};
      const initializer = new ModuleInitializer<typeof module>(() => Promise.resolve(module));
      try {
        await initializer.initialize();
      } catch (_) {
        expect.fail();
      }
    });
  });
});
