package br.edu.sentinela.service.strategy;

import br.edu.sentinela.model.Alert;

/** Define a ação de resposta para um alerta conforme a severidade. */
public interface AlertStrategy {

    void execute(Alert alert);
}
