import { PostagemService } from './services/postagem.service';
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Postagem } from './entities/postagem.Entidade';
import { PostagemController } from './controllers/postagem.controller';

@Module({
  imports: [TypeOrmModule.forFeature([Postagem])],
  providers: [PostagemService],
  controllers: [PostagemController],
  exports: [],
})
export class PostagemModule {}
