package br.com.inkinvite.domain.autenticacao;

import br.com.inkinvite.domain.DominioException;

public class UsuarioInvalido extends DominioException {
    public UsuarioInvalido() {
        super.mensagem = "As credenciais do usuário requisitado não pode ser encontrado. Tente novamente.";
    }
}
