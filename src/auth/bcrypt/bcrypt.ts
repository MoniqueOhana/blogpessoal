import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

@Injectable()
export class Bcrypt {
  async criptografarSenha(senha: string): Promise<string> {
    const saltos: number = 10;
    return await bcrypt.hash(senha, saltos);
  }

  async compararSenhas(
    senhaDigitada: string,
    senhaAcesso: string,
  ): Promise<boolean> {
    return await bcrypt.compare(senhaDigitada, senhaAcesso);
  }
}
