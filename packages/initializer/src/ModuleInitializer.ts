import { ModuleInitializerError } from './errors';

type InitializationFunction<T> = () => Promise<T>;

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
    if (console && console.warn) {
      console.warn(
        "Please prefer `initialize()` method over this setter. Otherwise we hope that you know what you're doing.",
      );
    }
    this._module = module;
  }

  constructor(initializationFunction: InitializationFunction<T>) {
    this.initializationFunction = initializationFunction;
  }

  initialize = () => {
    if (!this.initializationPromise) {
      this.initializationPromise = this.initializationFunction().then(this.onInitialization);
    }
    return this.initializationPromise;
  };

  private onInitialization = (module: T) => {
    this._module = module;
    return Promise.resolve();
  };
}
