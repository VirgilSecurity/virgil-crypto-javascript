import { ModuleAlreadyExistsError, ModuleNotFoundError } from './errors';

type InitializationFunction<T> = (...args: any[]) => Promise<T>;

export class ModuleInitializer {
  private readonly initFns = new Map<string, InitializationFunction<any>>();
  private readonly initPromises = new Map<string, Promise<void>>();
  private readonly modules = new Map<string, any>();
  private loadModulesPromise: Promise<void> | undefined;

  addModule = <T>(name: string, initFn: InitializationFunction<T>) => {
    if (this.initFns.has(name)) {
      throw new ModuleAlreadyExistsError();
    }
    this.loadModulesPromise = undefined;
    this.initFns.set(name, initFn);
  };

  getModule = <T>(name: string) => {
    if (!this.modules.has(name)) {
      throw new ModuleNotFoundError();
    }
    return this.modules.get(name) as T;
  };

  hasModule = (name: string) => this.modules.has(name);

  setModule = <T>(name: string, module: T) => {
    this.modules.set(name, module);
  };

  removeModule = (name: string) => {
    this.initFns.delete(name);
    this.initPromises.delete(name);
    this.modules.delete(name);
  };

  loadModule = (name: string, ...args: any[]) => {
    if (!this.initFns.has(name)) {
      throw new ModuleNotFoundError();
    }
    if (this.initPromises.has(name)) {
      return this.initPromises.get(name)!;
    }
    const initPromise = this.initFns.get(name)!(...args).then(module => {
      this.modules.set(name, module);
      return Promise.resolve();
    });
    this.initPromises.set(name, initPromise);
    return initPromise;
  };

  loadModules = (args?: { [name: string]: any[] }) => {
    if (this.loadModulesPromise) {
      return this.loadModulesPromise;
    }
    const myArgs = args || {};
    const names = Array.from(this.initFns.keys());
    const loadModules = names.map(name => {
      if (myArgs[name]) {
        return this.loadModule(name, ...myArgs[name]);
      }
      return this.loadModule(name);
    });
    this.loadModulesPromise = Promise.all(loadModules).then(() => Promise.resolve());
    return this.loadModulesPromise;
  };
}
