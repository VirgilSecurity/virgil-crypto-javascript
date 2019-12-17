export class ModuleAlreadyExistsError extends Error {
  constructor() {
    super('Module already exists.');
    Object.setPrototypeOf(this, ModuleAlreadyExistsError.prototype);
    this.name = 'ModuleAlreadyExistsError';
  }
}

export class ModuleNotFoundError extends Error {
  constructor() {
    super('Module not found.');
    Object.setPrototypeOf(this, ModuleNotFoundError.prototype);
    this.name = 'ModuleNotFoundError';
  }
}
