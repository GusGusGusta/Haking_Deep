// src/main.ts
import { bootstrapApplication } from '@angular/platform-browser';
import { appConfig } from './app/app.config'; // Importa tu configuración
import { AppComponent } from './app/app.component';

bootstrapApplication(AppComponent, appConfig) // Usa appConfig
  .catch((err) => console.error(err));