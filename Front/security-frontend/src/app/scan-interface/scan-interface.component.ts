// src/app/scan-interface/scan-interface.component.ts
import { Component, ElementRef, ViewChild, Inject, PLATFORM_ID, Renderer2, ChangeDetectorRef } from '@angular/core';
import { isPlatformBrowser, CommonModule } from '@angular/common';
import { ApiService } from '../api.service';
import { FormsModule } from '@angular/forms';
import html2pdf from 'html2pdf.js';

@Component({
  selector: 'app-scan-interface',
  standalone: true,
  imports: [
    FormsModule,
    CommonModule
  ],
  templateUrl: './scan-interface.component.html',
  styleUrls: ['./scan-interface.component.css']
})
export class ScanInterfaceComponent {
  @ViewChild('scanResultsContainer') scanResultsContainer!: ElementRef;

  urlDominio: string = '';
  escenarioSeleccionado: 'basic' | 'complete' = 'basic';
  gquery: string = '';
  
  scanResults: any = null;
  isLoading: boolean = false; 
  isGeneratingPdf: boolean = false; 
  errorMessage: string | null = null;
  currentStatusMessage: string = ''; // NUEVA propiedad para mensajes de estado

  constructor(
    private apiService: ApiService,
    @Inject(PLATFORM_ID) private platformId: Object,
    private renderer: Renderer2,
    private cdr: ChangeDetectorRef 
  ) { }

  objectKeys(obj: any): string[] {
    return obj ? Object.keys(obj) : [];
  }

  // Helper para crear delays con promesas (para async/await)
  private delay(ms: number) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // NUEVO: Método para mostrar progreso falso
  private async displayFakeProgress(scenario: 'basic' | 'complete'): Promise<void> {
    // Tiempos aproximados que me diste (en milisegundos)
    const initialDelay = 3000;       // Recibir solicitud
    const dnsDuration = 10000;         // DNS
    const nmapDuration = 30000;        // Nmap
    const googleDorksDuration = 20000; // Google Dorks
    const deepSeekDuration = 60000;    // DeepSeek (esta es la más larga y va al final)

    try {
      this.currentStatusMessage = 'Recibiendo solicitud y preparando escaneos...';
      this.cdr.detectChanges(); // Forzar actualización de UI
      await this.delay(initialDelay);
      if (!this.isLoading) return; // Detener si la carga real terminó

      this.currentStatusMessage = 'Realizando escaneo DNS...';
      this.cdr.detectChanges();
      await this.delay(dnsDuration);
      if (!this.isLoading) return;

      this.currentStatusMessage = 'Realizando escaneo Nmap (esto puede tardar)...';
      this.cdr.detectChanges();
      await this.delay(nmapDuration);
      if (!this.isLoading) return;
      
      // Whois es rápido, lo podemos agrupar o no mostrar un mensaje específico
      // this.currentStatusMessage = 'Realizando consulta Whois...';
      // this.cdr.detectChanges();
      // await this.delay(5000); // Estimación para Whois
      // if (!this.isLoading) return;


      if (scenario === 'complete') {
        this.currentStatusMessage = 'Consultando Google Dorks...';
        this.cdr.detectChanges();
        await this.delay(googleDorksDuration);
        if (!this.isLoading) return;
      }

      this.currentStatusMessage = 'Enviando datos para análisis con DeepSeek...';
      this.cdr.detectChanges();
      // El resto del tiempo es la espera de DeepSeek. 
      // No necesitamos más delays aquí si la API call ya está corriendo en paralelo.
      // El mensaje se mantendrá hasta que la API responda.
      // Si la API tarda más que la suma de estos delays, se mostrará este último mensaje.
      // Si tarda menos, this.isLoading se pondrá a false y este bucle de mensajes se cortará.

    } catch (error) {
      // En caso de que el delay falle, lo cual es improbable
      console.error("Error en displayFakeProgress:", error);
    }
  }

  enviarConsulta(): void {
    console.log('<<<<< MÉTODO enviarConsulta() LLAMADO >>>>> --- Hora:', new Date().toLocaleTimeString());
    
    if (this.isGeneratingPdf || this.isLoading) {
        console.log('enviarConsulta: Operación ya en curso. Saliendo.');
        return;
    }

    if (!this.urlDominio) {
      this.errorMessage = 'Por favor, ingresa una URL o Dominio.';
      return;
    }

    this.isLoading = true; 
    this.scanResults = null;
    this.errorMessage = null;
    this.currentStatusMessage = 'Iniciando...'; // Mensaje inicial
    this.cdr.detectChanges(); // Actualizar UI para mostrar mensaje inicial y estado de carga

    this.displayFakeProgress(this.escenarioSeleccionado); // Iniciar la secuencia de mensajes falsos

    const apiCall = this.escenarioSeleccionado === 'basic' ?
      this.apiService.realizarConsultaBasica(this.urlDominio) :
      this.apiService.realizarConsultaCompleta(this.urlDominio, this.gquery || undefined);

    apiCall.subscribe({
      next: (data) => {
        this.scanResults = data;
        this.isLoading = false; // Detiene la secuencia de mensajes falsos y el spinner
        this.currentStatusMessage = ''; // Limpiar mensaje de estado
        this.cdr.detectChanges();
      },
      error: (err: any) => {
        this.handleApiError(err, this.escenarioSeleccionado);
        // this.isLoading ya se setea a false en handleApiError
        // this.currentStatusMessage también se limpia en handleApiError
      }
    });
  }

  private handleApiError(err: any, tipoConsulta: string): void {
    console.error(`Error en consulta ${tipoConsulta}:`, err);
    let detailedError = 'Error desconocido del servidor.';
    // ... (lógica de handleApiError como la tenías) ...
    if (err.error) {
      if (typeof err.error === 'string') {
        if (err.error.includes("Traceback")) { detailedError = 'Error del servidor. Revisa la consola del backend.'; }
        else { detailedError = err.error; }
      } else if (typeof err.error === 'object' && err.error.error) { detailedError = err.error.error; }
      else if (err.message) { detailedError = err.message; }
    } else if (err.message) { detailedError = err.message; }
    
    this.errorMessage = `Error al realizar la consulta ${tipoConsulta}: ${detailedError}`;
    this.isLoading = false; 
    this.isGeneratingPdf = false;
    this.currentStatusMessage = ''; // Limpiar mensaje de estado también en error
    this.cdr.detectChanges(); 
  }

  public downloadReportAsPDF(event?: MouseEvent): void {
    // ... (tu método downloadReportAsPDF como en la última versión, sin cambios aquí) ...
    console.log('<<<<< MÉTODO downloadReportAsPDF() LLAMADO >>>>> --- Hora:', new Date().toLocaleTimeString());
    if (event) { 
        event.stopPropagation(); 
        event.preventDefault(); 
    }

    if (isPlatformBrowser(this.platformId)) {
      if (!this.scanResultsContainer || !this.scanResults) {
        this.errorMessage = "No hay resultados para descargar como PDF. Realiza un escaneo primero.";
        return;
      }
      if (this.isGeneratingPdf || this.isLoading) {
        console.log('downloadReportAsPDF: Operación ya en curso. Saliendo.');
        return;
      }

      this.isGeneratingPdf = true; 
      this.errorMessage = null;
      this.cdr.detectChanges();

      const elementToPrint = this.scanResultsContainer.nativeElement;
      const filename = `reporte_seguridad_${this.scanResults.url_dominio.replace(/\./g, '_')}_${this.scanResults.scenario}.pdf`;
      const deepseekPreElement = elementToPrint.querySelector('#deepseekAnalysisContent');
      
      const opt = { /* ... */ }; // tus opciones de html2pdf

      if (deepseekPreElement) this.renderer.addClass(deepseekPreElement, 'pdf-export-expand');
      
      setTimeout(() => { // setTimeout para permitir actualización de UI
        import('html2pdf.js').then(module => {
          const html2pdf = module.default;
          if (typeof html2pdf === 'function') {
            html2pdf().from(elementToPrint).set(opt).save()
              .then(() => { console.log('PDF generado.'); })
              .catch((err: any) => { this.errorMessage = 'Error al generar el PDF: ' + (err.message || err); console.error('Error PDF:', err); })
              .finally(() => {
                if (deepseekPreElement) this.renderer.removeClass(deepseekPreElement, 'pdf-export-expand');
                this.isGeneratingPdf = false; this.cdr.detectChanges();
              });
          } else { /* ... */ 
              if (deepseekPreElement) this.renderer.removeClass(deepseekPreElement, 'pdf-export-expand');
              this.isGeneratingPdf = false; this.cdr.detectChanges();
          }
        }).catch((err: any) => { /* ... */ 
          if (deepseekPreElement && deepseekPreElement.classList.contains('pdf-export-expand')) {
             this.renderer.removeClass(deepseekPreElement, 'pdf-export-expand');
          }
          this.isGeneratingPdf = false; this.cdr.detectChanges();
        });
      }, 0);
    } else { /* ... */ 
      this.isGeneratingPdf = false; 
    }
  }
}