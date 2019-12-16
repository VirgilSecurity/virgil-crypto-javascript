import { ModuleInitializerError } from './errors';

type InitializationFunction<T> = (...args: any[]) => Promise<T>;

export class ModuleInitializer<T> {
  private readonly initializationFunction: InitializationFunction<T>;
  private initializationPromise: Promise<void> | undefined;
  private _module: T | undefined;

  get isInitialized() {
    return typeof this._module !== 'undefined';
  }

  get module() {
    if (!this.isInitialized) {
      throw new ModuleInitializerError('Cannot get module before it was initialized.');
    }
    return this._module as T;
  }

  set module(module: T) {
    this._module = module;
  }

  constructor(initializationFunction: InitializationFunction<T>) {
    this.initializationFunction = initializationFunction;
  }

  initialize = (...args: any[]) => {
    if (!this.initializationPromise) {
      this.initializationPromise = this.initializationFunction(...args).then(module => {
        this._module = module;
        return Promise.resolve();
      });
    }
    return this.initializationPromise;
  };

  reset = () => {
    this.initializationPromise = undefined;
  };
}
