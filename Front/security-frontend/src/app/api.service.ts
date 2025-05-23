// src/app/api.service.ts
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class ApiService {
  private djangoApiUrl = 'http://localhost:8000/api'; // URL base de tu API Django

  constructor(private http: HttpClient) { }

  // Para la consulta básica
  realizarConsultaBasica(urlDominio: string): Observable<any> {
    const endpoint = `${this.djangoApiUrl}/consulta_basica_json/`;
    const body = { url_dominio: urlDominio };
    const httpOptions = {
      headers: new HttpHeaders({
        'Content-Type': 'application/json',
      })
    };
    return this.http.post(endpoint, body, httpOptions);
  }

  // Para la consulta completa
  realizarConsultaCompleta(urlDominio: string, gquery?: string): Observable<any> {
    const endpoint = `${this.djangoApiUrl}/consulta_completa_json/`;
    const body: any = { url_dominio: urlDominio };
    if (gquery) {
      body.gquery = gquery;
    }
    const httpOptions = {
      headers: new HttpHeaders({
        'Content-Type': 'application/json',
      })
    };
    return this.http.post(endpoint, body, httpOptions);
  }

  // Para obtener el reporte HTML (la respuesta será un blob si quieres manejar la descarga en Angular)
  // O simplemente puedes hacer un enlace directo a este endpoint en tu HTML.
  // Por ahora, nos enfocaremos en consumir el JSON.
}