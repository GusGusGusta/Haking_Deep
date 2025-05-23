import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ScanInterfaceComponent } from './scan-interface.component';

describe('ScanInterfaceComponent', () => {
  let component: ScanInterfaceComponent;
  let fixture: ComponentFixture<ScanInterfaceComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ScanInterfaceComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(ScanInterfaceComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
