import EventEmmiter from 'eventemitter3';

import { ModuleAlreadyExistsError, ModuleNotFoundError } from './errors';

type InitializationFunction<T> = (...args: any[]) => Promise<T>;

export enum ModuleInitializerEvents {
  load = 'load',
  remove = 'remove',
  error = 'error',
}

export class ModuleInitializer extends EventEmmiter {
  private readonly initFns = new Map<string, InitializationFunction<any>>();
  private readonly initPromises = new Map<string, Promise<void>>();
  private readonly modules = new Map<string, any>();
  private loadModulesPromise: Promise<void> | undefined;

  addModule = <T>(name: string, initFn: InitializationFunction<T>) => {
    if (this.initFns.has(name)) {
      const error = new ModuleAlreadyExistsError();
      this.emit(ModuleInitializerEvents.error, error, name, initFn);
      throw error;
    }
    this.loadModulesPromise = undefined;
    this.initFns.set(name, initFn);
  };

  getModule = <T>(name: string) => {
    if (!this.modules.has(name)) {
      const error = new ModuleNotFoundError();
      this.emit(ModuleInitializerEvents.error, error, name);
      throw error;
    }
    return this.modules.get(name) as T;
  };

  hasModule = (name: string) => this.modules.has(name);

  setModule = <T>(name: string, module: T) => {
    this.modules.set(name, module);
    this.emit(ModuleInitializerEvents.load, name, module);
  };

  removeModule = (name: string) => {
    this.initFns.delete(name);
    this.initPromises.delete(name);
    if (this.modules.has(name)) {
      const module = this.modules.get(name);
      this.modules.delete(name);
      this.emit(ModuleInitializerEvents.remove, name, module);
    }
  };

  loadModule = (name: string, ...args: any[]) => {
    if (!this.initFns.has(name)) {
      const error = new ModuleNotFoundError();
      this.emit(ModuleInitializerEvents.error, error, name, ...args);
      throw error;
    }
    if (this.initPromises.has(name)) {
      return this.initPromises.get(name)!;
    }
    const initPromise = this.initFns.get(name)!(...args).then(module => {
      this.modules.set(name, module);
      this.emit(ModuleInitializerEvents.load, name, module, ...args);
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
