// src/app/app.component.ts
import { Component } from '@angular/core';
import { RouterOutlet } from '@angular/router'; // Si usas routing
import { ScanInterfaceComponent } from './scan-interface/scan-interface.component'; // Importa tu componente
import { CommonModule } from '@angular/common'; // Para directivas comunes si las usas en app.component.html

@Component({
  selector: 'app-root',
  standalone: true,  // <--- MARCA COMO STANDALONE
  imports: [
    CommonModule,            // <--- IMPORTA CommonModule
    RouterOutlet,            // <--- IMPORTA RouterOutlet si usas <router-outlet>
    ScanInterfaceComponent   // <--- IMPORTA tu componente para poder usar <app-scan-interface>
  ],
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent {
  title = 'security-frontend'; // O el título que quieras
}