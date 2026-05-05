package br.edu.sentinela.service.chain;

/** Interface do padrão Chain of Responsibility para processamento de alertas. */
public interface AlertHandler {

    AlertHandler setNext(AlertHandler next);

    /** Processa o contexto e delega ao próximo handler, se houver. */
    AlertContext handle(AlertContext context);
}
