export class ModuleInitializerError extends Error {
  constructor(message: string) {
    super(message);
    Object.setPrototypeOf(this, ModuleInitializerError.prototype);
    this.name = 'ModuleInitializerError';
  }
}
