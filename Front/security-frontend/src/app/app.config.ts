// src/app/app.config.ts
import { ApplicationConfig, importProvidersFrom } from '@angular/core';
import { provideRouter } from '@angular/router';
import { routes } from './app.routes'; // Tus rutas, si las tienes definidas
import { provideClientHydration } from '@angular/platform-browser';

// Importa para HttpClient
import { HttpClientModule, provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';

export const appConfig: ApplicationConfig = {
  providers: [
    provideRouter(routes), 
    provideClientHydration(),
    // Añade provideHttpClient aquí para habilitar HttpClient en toda la aplicación
    // withInterceptorsFromDi() es para que los interceptores basados en DI funcionen como antes.
    // Si no usas interceptores complejos, provideHttpClient() solo podría ser suficiente.
    provideHttpClient(withInterceptorsFromDi()) 
  ]
};